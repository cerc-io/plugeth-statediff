package log

import (
	"github.com/inconshreveable/log15"
	"github.com/openrelayxyz/plugeth-utils/core"
)

type Logger = core.Logger

var (
	DefaultLogger core.Logger

	TestLogger = Log15Logger()
)

func init() {
	// The plugeth logger is only initialized with the geth runtime,
	// but tests expect to have a logger available, so default to this.
	DefaultLogger = TestLogger
}

func Trace(m string, a ...interface{}) { DefaultLogger.Trace(m, a...) }
func Debug(m string, a ...interface{}) { DefaultLogger.Debug(m, a...) }
func Info(m string, a ...interface{})  { DefaultLogger.Info(m, a...) }
func Warn(m string, a ...interface{})  { DefaultLogger.Warn(m, a...) }
func Crit(m string, a ...interface{})  { DefaultLogger.Crit(m, a...) }
func Error(m string, a ...interface{}) { DefaultLogger.Error(m, a...) }

func SetDefaultLogger(l core.Logger) {
	DefaultLogger = l
}

// Log15Logger returns a logger satisfying the same interface as geth's
func Log15Logger(ctx ...interface{}) wrapLog15 {
	return wrapLog15{log15.New(ctx...)}
}

type wrapLog15 struct{ log15.Logger }

func (l wrapLog15) New(ctx ...interface{}) Logger {
	return wrapLog15{l.Logger.New(ctx...)}
}

func (l wrapLog15) Trace(m string, a ...interface{}) {
	l.Logger.Debug(m, a...)
}

func (l wrapLog15) SetLevel(lvl int) {
	l.SetHandler(log15.LvlFilterHandler(log15.Lvl(lvl), l.GetHandler()))
}

// New returns a Logger that includes the contextual args in all output
// (workaround for missing method in plugeth)
func New(ctx ...interface{}) Logger {
	return ctxLogger{DefaultLogger, ctx}
}

type ctxLogger struct {
	base Logger
	ctx  []interface{}
}

func (l ctxLogger) Trace(m string, a ...interface{}) { l.base.Trace(m, append(l.ctx, a...)...) }
func (l ctxLogger) Debug(m string, a ...interface{}) { l.base.Debug(m, append(l.ctx, a...)...) }
func (l ctxLogger) Info(m string, a ...interface{})  { l.base.Info(m, append(l.ctx, a...)...) }
func (l ctxLogger) Warn(m string, a ...interface{})  { l.base.Warn(m, append(l.ctx, a...)...) }
func (l ctxLogger) Crit(m string, a ...interface{})  { l.base.Crit(m, append(l.ctx, a...)...) }
func (l ctxLogger) Error(m string, a ...interface{}) { l.base.Error(m, append(l.ctx, a...)...) }
