package crypt

import (
	"context"
	"database/sql"
	"fmt"
	"reflect"
	"strings"
)

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
