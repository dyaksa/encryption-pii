package crypto

import (
	"context"
	"database/sql"
	"fmt"
	"reflect"
	"regexp"
	"strings"

	"github.com/dyaksa/encryption-pii/crypto/hmacx"
	"github.com/dyaksa/encryption-pii/crypto/types"
	"github.com/dyaksa/encryption-pii/validate/nik"
	"github.com/dyaksa/encryption-pii/validate/npwp"
	"github.com/dyaksa/encryption-pii/validate/phone"
	"github.com/google/uuid"
)

type Entity interface{}

type Database interface {
	QueryContext(ctx context.Context, query string, args ...interface{}) (*sql.Rows, error)
}

func QueryContext[D Database, T Entity](ctx context.Context, db D, baseQuery string, queryParams []interface{}, iOptInitFunc func(*T), IOptInitValue func(T)) (t []T, err error) {
	rows, err := db.QueryContext(ctx, baseQuery, queryParams...)
	if err != nil {
		return
	}
	defer rows.Close()

	for rows.Next() {
		var i T
		if iOptInitFunc != nil {
			iOptInitFunc(&i)
		}

		colums := structToInterfaceScan(&i)
		err = rows.Scan(colums...)

		if err != nil {
			return
		}

		if IOptInitValue != nil {
			IOptInitValue(i)
		}

		t = append(t, i)
	}
	return
}

type FindTextHeapByHashParams struct {
	Hash string
}

type FindTextHeapRow struct {
	ID      uuid.UUID
	Content string
	Hash    string
}

type FindTextHeapByContentParams struct {
	Content string
}

type TextHeap struct {
	Content string
	Type    string
	Hash    string
}

func BuildQueryLike(ctx context.Context, tx *sql.Tx, data any, cond string) (str string, err error) {
	entityValue := reflect.ValueOf(data)
	entityType := entityValue.Type()

	for i := 0; i < entityType.NumField(); i++ {
		field := entityType.Field(i)
		bidxCol := field.Tag.Get("bidx_col")
		heapCol := field.Tag.Get("txt_heap_table")
		value := entityValue.Field(i).Interface()

		var query = new(strings.Builder)
		query.WriteString("SELECT content, hash FROM ")
		query.WriteString(heapCol)
		query.WriteString(" WHERE content ILIKE $1")

		rows, err := tx.QueryContext(ctx, query.String(), "%"+value.(string)+"%")
		if err != nil {
			return "", err
		}

		var heaps []string
		for rows.Next() {
			var i FindTextHeapRow
			err = rows.Scan(&i.Content, &i.Hash)
			if err != nil {
				return "", err
			}

			heaps = append(heaps, i.Hash)
		}

		var like []string
		for _, heap := range heaps {
			like = append(like, bidxCol+" ILIKE "+"'%"+heap+"%'")
		}

		str = strings.Join(like, " "+cond+" ")
	}
	return
}

func GenerateSQLConditions(data any) (strs []string) {
	entityValue := reflect.ValueOf(data)
	entityType := entityValue.Type()

	for i := 0; i < entityType.NumField(); i++ {
		field := entityType.Field(i)
		bidxCol := field.Tag.Get("bidx_col")
		value := entityValue.Field(i).Interface()

		if bidxCol == "" {
			continue
		}

		strs = append(strs, bidxCol+" ILIKE "+"'%"+value.(string)+"%'")
	}

	return
}

type ResultHeap struct {
	Column string `json:"column"`
	Value  string `json:"value"`
}

func (c *Crypto) BindHeap(entity any) (err error) {
	entityPtrValue := reflect.ValueOf(entity)
	if entityPtrValue.Kind() != reflect.Ptr {
		return fmt.Errorf("entity harus berupa pointer")
	}

	entityValue := entityPtrValue.Elem()
	entityType := entityValue.Type()

	for i := 0; i < entityType.NumField(); i++ {
		field := entityType.Field(i)
		if _, ok := field.Tag.Lookup("txt_heap_table"); ok {
			plainTextFieldName := field.Name[:len(field.Name)-4]
			bidxField := entityValue.FieldByName(field.Name)
			txtHeapTable := field.Tag.Get("txt_heap_table")

			switch originalValue := entityValue.FieldByName(plainTextFieldName).Interface().(type) {
			case types.AESChiper:
				str, heaps := c.buildHeap(originalValue.To(), txtHeapTable)
				err = c.saveToHeap(context.Background(), c.dbHeapPsql, heaps)
				if err != nil {
					return fmt.Errorf("failed to save to heap: %w", err)
				}
				bidxField.SetString(str)
			}
		}
	}
	return nil
}

func (c *Crypto) saveToHeap(ctx context.Context, db *sql.DB, textHeaps []TextHeap) (err error) {
	for _, th := range textHeaps {
		query := new(strings.Builder)
		query.WriteString("INSERT INTO ")
		query.WriteString(th.Type)
		query.WriteString(" (content, hash) VALUES ($1, $2)")
		if ok, _ := isHashExist(ctx, db, th.Type, FindTextHeapByHashParams{Hash: th.Hash}); !ok {
			_, err = db.ExecContext(ctx, query.String(), th.Content, th.Hash)
		}
	}
	return
}

func (c *Crypto) buildHeap(value string, typeHeap string) (s string, th []TextHeap) {
	var values = split(value)
	builder := new(strings.Builder)
	for _, value := range values {
		builder.WriteString(hmacx.HMACHash(c.HMACFunc(), value).Hash().ToLast8DigitValue())
		th = append(th, TextHeap{
			Content: strings.ToLower(value),
			Type:    typeHeap,
			Hash:    hmacx.HMACHash(c.HMACFunc(), value).Hash().ToLast8DigitValue(),
		})
	}
	return builder.String(), th
}

// Deprecated: any is deprecated. Use interface{} instead.
func InsertWithHeap[T Entity](c *Crypto, ctx context.Context, tx *sql.Tx, tableName string, entity any, generic T) (a T, err error) {
	entityValue := reflect.ValueOf(entity)
	entityType := entityValue.Type()
	var fieldNames []string
	var args []interface{}
	var placeholders []string

	var th []TextHeap
	for i := 0; i < entityType.NumField(); i++ {
		field := entityType.Field(i)
		fieldName := field.Tag.Get("db")
		if fieldName == "" {
			continue
		}

		fieldNames = append(fieldNames, fieldName)
		switch fieldValue := entityValue.Field(i).Interface().(type) {
		case types.NullUuid:
			if fieldValue.Valid {
				args = append(args, fieldValue.UUID)
			} else {
				args = append(args, nil)
			}
		case types.NullString:
			if fieldValue.Valid {
				args = append(args, fieldValue.String)
			} else {
				args = append(args, nil)
			}
		case types.NullTime:
			if fieldValue.Valid {
				args = append(args, fieldValue.Time)
			} else {
				args = append(args, nil)
			}
		case types.NullInt64:
			if fieldValue.Valid {
				args = append(args, fieldValue.Int64)
			} else {
				args = append(args, nil)
			}
		case types.NullFloat64:
			if fieldValue.Valid {
				args = append(args, fieldValue.Float64)
			} else {
				args = append(args, nil)
			}
		case types.NullBool:
			if fieldValue.Valid {
				args = append(args, fieldValue.Bool)
			} else {
				args = append(args, nil)
			}
		default:
			args = append(args, fieldValue)
		}

		if bidxCol := field.Tag.Get("bidx_col"); bidxCol != "" {
			fieldNames = append(fieldNames, bidxCol)
			placeholders = append(placeholders, "$"+fmt.Sprint(len(placeholders)+1))

			switch fieldValue := entityValue.Field(i).Interface().(type) {
			case types.AESChiper:
				str, heaps := buildHeap(c, fieldValue.To(), field.Tag.Get("txt_heap_table"))
				th = append(th, heaps...)
				args = append(args, str)
			}
		}
		placeholders = append(placeholders, "$"+fmt.Sprint(len(placeholders)+1))
	}

	query := fmt.Sprintf("INSERT INTO %s (%s) VALUES (%s) RETURNING id", tableName, strings.Join(fieldNames, ", "), strings.Join(placeholders, ", "))

	err = saveToHeap(ctx, c.dbHeapPsql, th)
	if err != nil {
		return a, fmt.Errorf("failed to save to heap please check heap db connection: %w", err)
	}

	stmt, err := tx.PrepareContext(ctx, query)
	if err != nil {
		return a, fmt.Errorf("failed to prepare statement: %w", err)
	}
	defer stmt.Close()

	err = stmt.QueryRowContext(ctx, args...).Scan(&a)
	if err != nil {
		return a, fmt.Errorf("failed to execute statement: %w", err)
	}

	return a, nil
}

// Deprecated: any is deprecated. Use interface{} instead.
func UpdateWithHeap(c *Crypto, ctx context.Context, tx *sql.Tx, tableName string, entity any, id string) error {
	entityValue := reflect.ValueOf(entity)
	entityType := entityValue.Type()

	var fieldNames []string
	var placeholders []string
	var args []interface{}

	var th []TextHeap
	for i := 0; i < entityType.NumField(); i++ {
		field := entityType.Field(i)
		fieldName := field.Tag.Get("db")
		if fieldName == "" {
			continue
		}

		fieldNames = append(fieldNames, fieldName)
		switch fieldValue := entityValue.Field(i).Interface().(type) {
		case types.NullUuid:
			if fieldValue.Valid {
				args = append(args, fieldValue.UUID)
			} else {
				args = append(args, nil)
			}
		case types.NullString:
			if fieldValue.Valid {
				args = append(args, fieldValue.String)
			} else {
				args = append(args, nil)
			}
		case types.NullTime:
			if fieldValue.Valid {
				args = append(args, fieldValue.Time)
			} else {
				args = append(args, nil)
			}
		case types.NullInt64:
			if fieldValue.Valid {
				args = append(args, fieldValue.Int64)
			} else {
				args = append(args, nil)
			}
		case types.NullFloat64:
			if fieldValue.Valid {
				args = append(args, fieldValue.Float64)
			} else {
				args = append(args, nil)
			}
		case types.NullBool:
			if fieldValue.Valid {
				args = append(args, fieldValue.Bool)
			} else {
				args = append(args, nil)
			}
		default:
			args = append(args, fieldValue)
		}

		if bidxCol := field.Tag.Get("bidx_col"); bidxCol != "" {
			fieldNames = append(fieldNames, bidxCol)
			placeholders = append(placeholders, "$"+fmt.Sprint(len(placeholders)+1))

			switch fieldValue := entityValue.Field(i).Interface().(type) {
			case types.AESChiper:
				str, heaps := buildHeap(c, fieldValue.To(), field.Tag.Get("txt_heap_table"))
				th = append(th, heaps...)
				args = append(args, str)
			}
		}
		placeholders = append(placeholders, "$"+fmt.Sprint(len(placeholders)+1))
	}

	query := "UPDATE " + tableName + " SET "
	for i, field := range fieldNames {
		query += field + " = " + placeholders[i] + ", "
	}
	query = strings.TrimSuffix(query, ", ")
	query += " WHERE id = '" + id + "'"

	stmt, err := tx.PrepareContext(ctx, query)
	if err != nil {
		return fmt.Errorf("failed to prepare statement: %w", err)
	}
	defer stmt.Close()

	_, err = stmt.ExecContext(ctx, args...)
	if err != nil {
		return fmt.Errorf("failed to execute statement: %w", err)
	}

	err = saveToHeap(ctx, c.dbHeapPsql, th)
	if err != nil {
		return fmt.Errorf("failed to save to heap: %w", err)
	}

	return nil
}

type ILikeParams struct {
	ColumnHeap string
	Hash       []string
}

func QueryLike[T Entity](ctx context.Context, basQuery string, tx *sql.Tx, iOptionalFilter func(*ILikeParams), iOptInitFunc func(*T)) (t []T, err error) {
	var args []interface{}
	if iOptionalFilter != nil {
		var likeParams ILikeParams
		iOptionalFilter(&likeParams)
		basQuery, args = buildLikeQuery(likeParams.ColumnHeap, basQuery, likeParams.Hash)
	}

	rows, err := tx.QueryContext(ctx, basQuery, args...)
	if err != nil {
		return
	}
	defer rows.Close()

	for rows.Next() {
		var i T
		if iOptInitFunc != nil {
			iOptInitFunc(&i)
		}
		entityValue := reflect.ValueOf(&i).Elem()
		entityType := entityValue.Type()

		scanArgs := make([]interface{}, entityType.NumField())

		for i := 0; i < entityType.NumField(); i++ {
			field := entityValue.Field(i).Addr().Interface()
			scanArgs[i] = field
		}

		err = rows.Scan(scanArgs...)
		if err != nil {
			return
		}

		t = append(t, i)
	}
	return
}

func buildHeap(c *Crypto, value string, typeHeap string) (s string, th []TextHeap) {
	var values = split(value)
	builder := new(strings.Builder)
	for _, value := range values {
		builder.WriteString(hmacx.HMACHash(c.HMACFunc(), value).Hash().ToLast8DigitValue())
		th = append(th, TextHeap{
			Content: strings.ToLower(value),
			Type:    typeHeap,
			Hash:    hmacx.HMACHash(c.HMACFunc(), value).Hash().ToLast8DigitValue(),
		})
	}
	return builder.String(), th
}

func SearchContents(ctx context.Context, tx *sql.Tx, table string, args FindTextHeapByContentParams) (heaps []string, err error) {
	var query = new(strings.Builder)
	query.WriteString("SELECT content, hash FROM ")
	query.WriteString(table)
	query.WriteString(" WHERE content ILIKE $1")
	rows, err := tx.QueryContext(ctx, query.String(), "%"+args.Content+"%")
	if err != nil {
		return
	}
	defer rows.Close()

	seen := make(map[string]interface{})
	for rows.Next() {
		var i FindTextHeapRow
		err = rows.Scan(&i.Content, &i.Hash)
		if err != nil {
			return
		}
		if _, exist := seen[i.Hash]; !exist {
			heaps = append(heaps, i.Hash)
			seen[i.Hash] = struct{}{}
		}
	}
	return
}

func saveToHeap(ctx context.Context, db *sql.DB, textHeaps []TextHeap) (err error) {
	for _, th := range textHeaps {
		query := new(strings.Builder)
		query.WriteString("INSERT INTO ")
		query.WriteString(th.Type)
		query.WriteString(" (content, hash) VALUES ($1, $2)")
		if ok, _ := isHashExist(ctx, db, th.Type, FindTextHeapByHashParams{Hash: th.Hash}); !ok {
			_, err = db.ExecContext(ctx, query.String(), th.Content, th.Hash)
		}
	}
	return
}

func isHashExist(ctx context.Context, db *sql.DB, typeHeap string, args FindTextHeapByHashParams) (bool, error) {
	var query = new(strings.Builder)
	query.WriteString("SELECT hash FROM ")
	query.WriteString(typeHeap)
	query.WriteString(" WHERE hash = $1")
	row := db.QueryRowContext(ctx, query.String(), args.Hash)
	var i FindTextHeapRow
	err := row.Scan(&i.Hash)
	if err != nil {
		return false, err
	}
	if i.Hash == args.Hash {
		return true, nil
	}
	return false, nil
}

func split(value string) (s []string) {
	var sep = " "
	reg := "[a-zA-Z0-9]+"
	regex := regexp.MustCompile(reg)
	switch {
	case validateEmail(value):
		sep = "@"
	case phone.IsValid((value)):
		parse, err := phone.Parse(value)
		if err != nil {
			return
		}
		value = parse.ToString()
		sep = "-"
	case nik.IsValid((value)) || npwp.IsValid((value)):
		parse, err := nik.Parse(value)
		if err != nil {
			return
		}
		value = parse.ToString()
		sep = "."
	}
	parts := strings.Split(value, sep)
	for _, part := range parts {
		matches := regex.FindAllString(part, -1)
		s = append(s, matches...)
	}

	return
}

func validateEmail(email string) bool {
	// Define the email regex pattern
	const emailRegexPattern = `^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`

	// Compile the regex pattern
	re := regexp.MustCompile(emailRegexPattern)

	// Match the input email with the regex pattern
	return re.MatchString(email)
}

func buildLikeQuery(column, baseQuery string, terms []string) (string, []interface{}) {
	var likeClauses []string
	var args []interface{}

	for _, term := range terms {
		likeClauses = append(likeClauses, column+" LIKE $"+fmt.Sprint(len(args)+1))
		args = append(args, "%"+term+"%")
	}

	fullQuery := fmt.Sprintf("%s WHERE %s", baseQuery, strings.Join(likeClauses, " OR "))

	return fullQuery, args
}

func structToInterfaceScan(v interface{}) []interface{} {
	s := reflect.ValueOf(v).Elem()
	numCols := s.NumField()
	columns := make([]interface{}, numCols)
	for i := 0; i < numCols; i++ {
		field := s.Field(i)
		columns[i] = field.Addr().Interface()
	}
	return columns
}
