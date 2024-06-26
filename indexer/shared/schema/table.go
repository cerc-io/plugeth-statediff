// Copyright 2022 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

package schema

import (
	"fmt"
	"strings"

	"github.com/thoas/go-funk"
)

type colType int

const (
	Dinteger colType = iota
	Dboolean
	Dbigint
	Dnumeric
	Dbytea
	Dvarchar
	Dtext
)

type ConflictClause struct {
	Target []string
	Update []string
}

type Column struct {
	Name  string
	Type  colType
	Array bool
}

type Table struct {
	Name    string
	Columns []Column

	UpsertClause ConflictClause
}

func OnConflict(target ...string) ConflictClause {
	return ConflictClause{Target: target}
}
func (c ConflictClause) Set(fields ...string) ConflictClause {
	c.Update = fields
	return c
}

// TableName returns a pgx-compatible table name.
func (tbl *Table) TableName() []string {
	return strings.Split(tbl.Name, ".")
}

// ColumnNames returns the ordered list of column names.
func (tbl *Table) ColumnNames() []string {
	var names []string
	for _, col := range tbl.Columns {
		names = append(names, col.Name)
	}
	return names
}

// PreparedInsert returns a pgx/sqlx-compatible SQL prepared insert statement for the table
// using positional placeholders.
// If upsert is true, include an ON CONFLICT clause handling column updates.
func (tbl *Table) PreparedInsert(upsert bool) string {
	var colnames, placeholders []string
	for i, col := range tbl.Columns {
		colnames = append(colnames, col.Name)
		placeholders = append(placeholders, fmt.Sprintf("$%d", i+1))
	}
	suffix := " ON CONFLICT"
	if len(tbl.UpsertClause.Target) > 0 {
		suffix += fmt.Sprintf(" (%s)", strings.Join(tbl.UpsertClause.Target, ", "))
	}
	if upsert && len(tbl.UpsertClause.Update) != 0 {
		var update_placeholders []string
		for _, name := range tbl.UpsertClause.Update {
			update_placeholders = append(update_placeholders, "EXCLUDED."+name)
		}
		suffix += fmt.Sprintf(
			" DO UPDATE SET (%s) = ROW(%s)",
			strings.Join(tbl.UpsertClause.Update, ", "), strings.Join(update_placeholders, ", "),
		)
	} else {
		suffix += " DO NOTHING"
	}

	return fmt.Sprintf(
		"INSERT INTO %s (%s) VALUES (%s)",
		tbl.Name, strings.Join(colnames, ", "), strings.Join(placeholders, ", "),
	) + suffix
}

type colfmt = func(interface{}) string

func sprintf(f string) colfmt {
	return func(x interface{}) string { return fmt.Sprintf(f, x) }
}

func (typ colType) csvFormatter() colfmt {
	switch typ {
	case Dinteger:
		return sprintf("%d")
	case Dboolean:
		return func(x interface{}) string {
			if x.(bool) {
				return "t"
			}
			return "f"
		}
	case Dbigint:
		return sprintf("%s")
	case Dnumeric:
		return sprintf("%s")
	case Dbytea:
		return sprintf(`\x%x`)
	case Dvarchar:
		return sprintf("%s")
	case Dtext:
		return sprintf("%s")
	default:
		panic("invalid column type")
	}
}

// ToCsvRow converts a list of values to a list of strings suitable for CSV output.
func (tbl *Table) ToCsvRow(args ...interface{}) []string {
	var row []string
	for i, col := range tbl.Columns {
		value := col.Type.csvFormatter()(args[i])

		if col.Array {
			valueList := funk.Map(args[i], col.Type.csvFormatter()).([]string)
			value = fmt.Sprintf("{%s}", strings.Join(valueList, ","))
		}

		row = append(row, value)
	}
	return row
}

// VarcharColumns returns the names of columns with type VARCHAR.
func (tbl *Table) VarcharColumns() []string {
	columns := funk.Filter(tbl.Columns, func(col Column) bool {
		return col.Type == Dvarchar
	}).([]Column)

	columnNames := funk.Map(columns, func(col Column) string {
		return col.Name
	}).([]string)
	return columnNames
}

func formatSpec(typ colType) string {
	switch typ {
	case Dinteger:
		return "%d"
	case Dboolean:
		return "%t"
	case Dbytea:
		return `'\x%x'`
	default:
		return "'%s'"
	}
}

// FmtStringInsert returns a format string for creating a Postgres insert statement.
func (tbl *Table) FmtStringInsert() string {
	var colnames, placeholders []string
	for _, col := range tbl.Columns {
		colnames = append(colnames, col.Name)
		placeholders = append(placeholders, formatSpec(col.Type))
	}
	return fmt.Sprintf(
		"INSERT INTO %s (%s) VALUES (%s);",
		tbl.Name, strings.Join(colnames, ", "), strings.Join(placeholders, ", "),
	)
}
