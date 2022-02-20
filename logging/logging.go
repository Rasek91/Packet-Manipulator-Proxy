package logging

import (
	"fmt"
	"os"

	nested "github.com/antonfisher/nested-logrus-formatter"
	conntrack "github.com/florianl/go-conntrack"
	log "github.com/sirupsen/logrus"
)

func Setup() {
	/*file, error := os.OpenFile("testlogrus.log", os.O_APPEND|os.O_CREATE|os.O_RDWR, 0666)

	if error != nil {
		fmt.Printf("error opening file: %v", error)
	}*/

	log.SetFormatter(&nested.Formatter{
		HideKeys:    true,
		FieldsOrder: []string{"ipTuple", "function", "socket", "data"},
	})
	log.SetOutput(os.Stdout)
	log.SetLevel(log.DebugLevel)
	Log("trace", map[string]interface{}{"function": "Setup"}, "Logging set up")
}

func Log(loglevel string, fields map[string]interface{}, arguments ...interface{}) {
	level, err := log.ParseLevel(loglevel)

	if err != nil {
		return
	}

	switch level {
	case log.PanicLevel:
		log.WithFields(fields).Panic(arguments...)
	case log.FatalLevel:
		log.WithFields(fields).Fatal(arguments...)
	case log.ErrorLevel:
		log.WithFields(fields).Error(arguments...)
	case log.WarnLevel:
		log.WithFields(fields).Warn(arguments...)
	case log.InfoLevel:
		log.WithFields(fields).Info(arguments...)
	case log.DebugLevel:
		log.WithFields(fields).Debug(arguments...)
	case log.TraceLevel:
		log.WithFields(fields).Trace(arguments...)
	}
}

type IPTuple conntrack.IPTuple

func (ipTuple *IPTuple) String() (formatted string) {
	formatted = fmt.Sprintf("%v|%v:%d|%v:%d", *ipTuple.Proto.Number, ipTuple.Src, *ipTuple.Proto.SrcPort, ipTuple.Dst, *ipTuple.Proto.DstPort)
	return
}
