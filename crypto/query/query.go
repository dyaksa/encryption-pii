package query

import (
	"context"
	"database/sql"
	"fmt"
	"reflect"
	"regexp"
	"strings"

	"github.com/dyaksa/encryption-pii/crypto"
	"github.com/dyaksa/encryption-pii/crypto/types"
	"github.com/google/uuid"
)

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

func InsertWithHeap(c *crypto.Crypto, ctx context.Context, tx *sql.Tx, tableName string, entity any) (err error) {
	entityValue := reflect.ValueOf(entity)
	entityType := entityValue.Type()

	fieldNames := make([]string, entityType.NumField())
	placeholders := make([]string, entityType.NumField())
	args := make([]interface{}, entityType.NumField())

	var th []TextHeap
	for i := 0; i < entityType.NumField(); i++ {
		field := entityType.Field(i)
		fieldNames[i] = field.Tag.Get("db")
		args[i] = entityValue.Field(i).Interface()

		if field.Tag.Get("bidx_col") != "" {
			fieldNames = append(fieldNames, field.Tag.Get("bidx_col"))
			placeholders = append(placeholders, "$"+fmt.Sprint(len(placeholders)+1))

			switch entityValue.Field(i).Interface().(type) {
			case types.AESChiper:
				fieldValue := entityValue.Field(i).Interface().(types.AESChiper)
				str, heaps := BuildHeap(c, fieldValue.To(), field.Tag.Get("txt_heap_table"))
				th = append(th, heaps...)
				args = append(args, str)
			}
		}
		placeholders[i] = "$" + fmt.Sprint(i+1)
	}

	query := fmt.Sprintf("INSERT INTO %s (%s) VALUES (%s)", tableName, strings.Join(fieldNames, ", "), strings.Join(placeholders, ", "))

	stmt, err := tx.PrepareContext(ctx, query)
	if err != nil {
		return fmt.Errorf("failed to prepare statement: %w", err)
	}
	defer stmt.Close()

	_, err = stmt.ExecContext(ctx, args...)
	if err != nil {
		return fmt.Errorf("failed to execute statement: %w", err)
	}

	err = SaveToHeap(ctx, tx, th)
	if err != nil {
		return fmt.Errorf("failed to save to heap: %w", err)
	}
	return nil
}

func UpdateWithHeap(c *crypto.Crypto, ctx context.Context, tx *sql.Tx, tableName string, entity any, id string) error {
	entityValue := reflect.ValueOf(entity)
	entityType := entityValue.Type()

	fieldNames := make([]string, entityType.NumField())
	placeholders := make([]string, entityType.NumField())
	args := make([]interface{}, entityType.NumField())

	var th []TextHeap
	for i := 0; i < entityType.NumField(); i++ {
		field := entityType.Field(i)
		fieldNames[i] = field.Tag.Get("db")
		args[i] = entityValue.Field(i).Interface()

		if field.Tag.Get("bidx_col") != "" {
			fieldNames = append(fieldNames, field.Tag.Get("bidx_col"))
			placeholders = append(placeholders, "$"+fmt.Sprint(len(placeholders)+1))

			switch entityValue.Field(i).Interface().(type) {
			case types.AESChiper:
				fieldValue := entityValue.Field(i).Interface().(types.AESChiper)
				str, heaps := BuildHeap(c, fieldValue.To(), field.Tag.Get("txt_heap_table"))
				th = append(th, heaps...)
				args = append(args, str)
			}
		}
		placeholders[i] = "$" + fmt.Sprint(i+1)
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

	err = SaveToHeap(ctx, tx, th)
	if err != nil {
		return fmt.Errorf("failed to save to heap: %w", err)
	}

	return nil
}

type Entity interface{}

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

func BuildHeap(c *crypto.Crypto, value string, typeHeap string) (s string, th []TextHeap) {
	var values = split(value)
	builder := new(strings.Builder)
	for _, value := range values {
		builder.WriteString(c.Hash(value))
		th = append(th, TextHeap{
			Content: strings.ToLower(value),
			Type:    typeHeap,
			Hash:    c.Hash(value),
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
	for rows.Next() {
		var i FindTextHeapRow
		err = rows.Scan(&i.Content, &i.Hash)
		if err != nil {
			return
		}
		heaps = append(heaps, i.Hash)
	}
	return
}

func SaveToHeap(ctx context.Context, tx *sql.Tx, textHeaps []TextHeap) (err error) {
	for _, th := range textHeaps {
		query := new(strings.Builder)
		query.WriteString("INSERT INTO ")
		query.WriteString(th.Type)
		query.WriteString(" (content, hash) VALUES ($1, $2)")
		if ok, _ := isHashExist(ctx, tx, th.Type, FindTextHeapByHashParams{Hash: th.Hash}); !ok {
			_, err = tx.ExecContext(ctx, query.String(), th.Content, th.Hash)
		}
	}
	return
}

func isHashExist(ctx context.Context, tx *sql.Tx, typeHeap string, args FindTextHeapByHashParams) (bool, error) {
	var query = new(strings.Builder)
	query.WriteString("SELECT hash FROM ")
	query.WriteString(typeHeap)
	query.WriteString(" WHERE hash = $1")
	row := tx.QueryRowContext(ctx, query.String(), args.Hash)
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
	if validateEmail(value) {
		sep = "@"
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
