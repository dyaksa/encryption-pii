package crypt

import (
	"context"
	"database/sql"
	"fmt"
	"reflect"
	"strings"

	"github.com/dyaksa/encryption-pii/crypt/types"
)

type Entity interface{}

type ILikeParams struct {
	ColumnHeap string
	Hash       []string
}

func (l *Lib) UpdateWithHeap(ctx context.Context, tx *sql.Tx, tableName string, entity any, id string) error {
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
			case types.AEADString:
				fieldValue := entityValue.Field(i).Interface().(types.AEADString)
				str, heaps := l.BuildHeap(fieldValue.To(), field.Tag.Get("txt_heap_table"))
				th = append(th, heaps...)
				args = append(args, str)
			case types.AEADInt64:
				fieldValue := entityValue.Field(i).Interface().(types.AEADInt64)
				str, heaps := l.BuildHeap(fmt.Sprintf("%d", fieldValue.To()), field.Tag.Get("txt_heap_table"))
				th = append(th, heaps...)
				args = append(args, str)
			case types.AEADFloat64:
				fieldValue := entityValue.Field(i).Interface().(types.AEADFloat64)
				str, heaps := l.BuildHeap(fmt.Sprintf("%f", fieldValue.To()), field.Tag.Get("txt_heap_table"))
				th = append(th, heaps...)
				args = append(args, str)
			case types.AEADTime:
				fieldValue := entityValue.Field(i).Interface().(types.AEADTime)
				str, heaps := l.BuildHeap(fieldValue.To().String(), field.Tag.Get("txt_heap_table"))
				th = append(th, heaps...)
				args = append(args, str)
			case types.AEADBool:
				fieldValue := entityValue.Field(i).Interface().(types.AEADBool)
				str, heaps := l.BuildHeap(fmt.Sprintf("%t", fieldValue.To()), field.Tag.Get("txt_heap_table"))
				th = append(th, heaps...)
				args = append(args, str)
			}
		}
		placeholders[i] = "$" + fmt.Sprint(i+1)
	}

	query := "UPDATE " + tableName + " SET "
	for i, field := range fieldNames {
		query += field + "=" + placeholders[i] + ", "
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

	err = l.SaveToHeap(ctx, tx, th)
	if err != nil {
		return fmt.Errorf("failed to save to heap: %w", err)
	}

	return nil
}

func (l *Lib) InsertWithHeap(ctx context.Context, tx *sql.Tx, tableName string, entity any) error {
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
			case types.AEADString:
				fieldValue := entityValue.Field(i).Interface().(types.AEADString)
				str, heaps := l.BuildHeap(fieldValue.To(), field.Tag.Get("txt_heap_table"))
				th = append(th, heaps...)
				args = append(args, str)
			case types.AEADInt64:
				fieldValue := entityValue.Field(i).Interface().(types.AEADInt64)
				str, heaps := l.BuildHeap(fmt.Sprintf("%d", fieldValue.To()), field.Tag.Get("txt_heap_table"))
				th = append(th, heaps...)
				args = append(args, str)
			case types.AEADFloat64:
				fieldValue := entityValue.Field(i).Interface().(types.AEADFloat64)
				str, heaps := l.BuildHeap(fmt.Sprintf("%f", fieldValue.To()), field.Tag.Get("txt_heap_table"))
				th = append(th, heaps...)
				args = append(args, str)
			case types.AEADTime:
				fieldValue := entityValue.Field(i).Interface().(types.AEADTime)
				str, heaps := l.BuildHeap(fieldValue.To().String(), field.Tag.Get("txt_heap_table"))
				th = append(th, heaps...)
				args = append(args, str)
			case types.AEADBool:
				fieldValue := entityValue.Field(i).Interface().(types.AEADBool)
				str, heaps := l.BuildHeap(fmt.Sprintf("%t", fieldValue.To()), field.Tag.Get("txt_heap_table"))
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

	err = l.SaveToHeap(ctx, tx, th)
	if err != nil {
		return fmt.Errorf("failed to save to heap: %w", err)
	}
	return nil
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
