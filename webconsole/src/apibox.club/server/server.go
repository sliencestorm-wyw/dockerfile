package server

import (
	"apibox.club/utils"
	"net"
	"net/http"
	"net/http/fcgi"
	"os"
	"runtime"
	"strings"
	"time"
)

var (
	ABC_Conf, conf_err = apibox.Get_Conf()
)

func init() {
	runtime.GOMAXPROCS(runtime.NumCPU())
	if nil != conf_err {
		apibox.Log_Fatal(conf_err.Error())
	}
	_ = ABC_Conf.Web.Addr
}

func GetPID() string {
	return apibox.ToStr(os.Getpid())
}

func Run() {
	go func() {
		for {
			err := apibox.WritePidFile(apibox.PidPath, GetPID())
			if nil != err {
				apibox.Log_Fatal(err)
				break
			}
			time.Sleep(time.Duration(1 * time.Second))
		}
	}()

	if ABC_Conf.Web.Daemon {
		ret, err := apibox.Daemon(0, 0)
		if nil != err && ret == -1 {
			apibox.Log_Fatal(err)
			return
		}
	}

	runMsgArr := make([]string, 0, 0)
	runMsgArr = append(runMsgArr, "==>")
	runMsgArr = append(runMsgArr, "Web server running.")
	runMsgArr = append(runMsgArr, "PID:"+GetPID()+",")
	runMsgArr = append(runMsgArr, "Addr:"+ABC_Conf.Web.Addr+".")

	if ABC_Conf.Web.EnableFcgi {
		runMsgArr = append(runMsgArr, "Fcgi:"+apibox.ToStr(ABC_Conf.Web.EnableFcgi)+".")
	}

	if ABC_Conf.Web.EnableTLS {
		runMsgArr = append(runMsgArr, "SSL:"+apibox.ToStr(ABC_Conf.Web.EnableTLS)+",")
		runMsgArr = append(runMsgArr, "TLS_Addr:"+apibox.ToStr(ABC_Conf.Web.TlsAddr)+",")
		runMsgArr = append(runMsgArr, "TLS_Url:"+apibox.ToStr(ABC_Conf.Web.TlsUrl)+".")
	}

	runMsg := strings.Join(runMsgArr, " ")

	apibox.Log_Info(runMsg)

	if ABC_Conf.Web.EnableFcgi {
		listener, err := net.Listen("tcp", ABC_Conf.Web.Addr)
		if err != nil {
			apibox.Log_Fatal(err.Error())
			return
		}
		err = fcgi.Serve(listener, DefaultServeMux)
		if nil != err {
			apibox.Log_Fatal(err)
			return
		}
	} else {
		if ABC_Conf.Web.EnableTLS {
			go func() {
				err := http.ListenAndServe(ABC_Conf.Web.Addr, RedirectHandler(ABC_Conf.Web.TlsUrl, http.StatusMovedPermanently))
				if nil != err {
					apibox.Log_Fatal(err)
					return
				}
			}()

			certFile := apibox.ConfDir + apibox.PathSeparator + ABC_Conf.Web.TlsCert
			keyFile := apibox.ConfDir + apibox.PathSeparator + ABC_Conf.Web.TlsKey

			err := http.ListenAndServeTLS(ABC_Conf.Web.TlsAddr, certFile, keyFile, DefaultServeMux)
			if nil != err {
				apibox.Log_Fatal(err)
				return
			}
		} else {
			err := http.ListenAndServe(ABC_Conf.Web.Addr, DefaultServeMux)
			if nil != err {
				apibox.Log_Fatal(err)
				return
			}
		}
	}
}
