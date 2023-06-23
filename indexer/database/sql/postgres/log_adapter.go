// Copyright © 2023 Cerc

// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.

// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

package postgres

import (
	"context"

	"github.com/jackc/pgx/v4"

	"github.com/cerc-io/plugeth-statediff/utils/log"
)

type LogAdapter struct {
	l log.Logger
}

func NewLogAdapter(l log.Logger) *LogAdapter {
	return &LogAdapter{l: l}
}

func (l *LogAdapter) Log(ctx context.Context, level pgx.LogLevel, msg string, data map[string]interface{}) {
	args := make([]interface{}, 0)
	for key, value := range data {
		if value != nil {
			args = append(args, key, value)
		}
	}

	logger := l.l
	switch level {
	case pgx.LogLevelTrace:
		logger.Trace(msg, args...)
	case pgx.LogLevelDebug:
		logger.Debug(msg, args...)
	case pgx.LogLevelInfo:
		logger.Info(msg, args...)
	case pgx.LogLevelWarn:
		logger.Warn(msg, args...)
	case pgx.LogLevelError:
		logger.Error(msg, args...)
	default:
		logger.Error(msg, "INVALID_PGX_LOG_LEVEL", level)
	}
}
