package proxies

import (
	"fmt"
	"os"

	nested "github.com/antonfisher/nested-logrus-formatter"
	conntrack "github.com/florianl/go-conntrack"
	log "github.com/sirupsen/logrus"
)

func Setup_log() {
	/*file, error := os.OpenFile("testlogrus.log", os.O_APPEND|os.O_CREATE|os.O_RDWR, 0666)

	if error != nil {
		fmt.Printf("error opening file: %v", error)
	}*/

	log.SetFormatter(&nested.Formatter{
		HideKeys:    true,
		FieldsOrder: []string{"ip_tuple", "socket", "data"},
	})
	log.SetOutput(os.Stdout)
	log.SetLevel(log.DebugLevel)
}

func print_ip_tuple(ip_tuple *conntrack.IPTuple) string {
	return fmt.Sprintf("%v|%v:%d|%v:%d", *ip_tuple.Proto.Number, ip_tuple.Src, *ip_tuple.Proto.SrcPort, ip_tuple.Dst, *ip_tuple.Proto.DstPort)
}
