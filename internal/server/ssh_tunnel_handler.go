package server

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/TylerZeroMaster/httptunnel"
)

var hijacker = httptunnel.Hijacker{}

type SSHTunnelHandler struct{}

func (handler SSHTunnelHandler) sendHttpResp(w http.ResponseWriter) {
	w.Header().Set("Connection", "upgrade")
	w.Header().Set("Upgrade", "ssh")
	w.WriteHeader(http.StatusSwitchingProtocols)
}

func (handler SSHTunnelHandler) getSSHAddress(r *http.Request) string {
	sshHost := r.Header.Get("x-ssh-host")
	sshPort := r.Header.Get("x-ssh-port")
	if len(sshHost) == 0 {
		sshHost = "localhost"
	}
	if len(sshPort) == 0 {
		sshPort = "22"
	}
	return fmt.Sprintf("%s:%s", sshHost, sshPort)
}

func (handler SSHTunnelHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	log := log.With().Str("url", r.URL.String()).Logger()
	log.Info().Msg("Connection opened")
	defer log.Info().Msg("Connection closed")
	address := handler.getSSHAddress(r)
	log.Debug().Str("address", address).Msg("dialing ssh")
	if sshConn, err := net.DialTimeout("tcp", address, 45*time.Second); err != nil {
		log.Error().Err(err).Msg("dial ssh")
		http.Error(w, err.Error(), 500)
	} else {
		// Unbox the tcp conn from the net.Conn interface so we can call
		// WriteTo/ReadFrom directly. These try to use splice, or similar,
		// to copy between pipes without copying into user address space
		// see `man 2 splice` and `net/tcpsock_posix.go` for more info
		sshTcpConn := httptunnel.AssertTCPConn(sshConn)
		handler.sendHttpResp(w)
		if httpConn, brw, err := hijacker.Hijack(w, r); err != nil {
			log.Error().Err(err).Msg("hijack")
		} else {
			defer httpConn.Close()
			httpTcpConn := httptunnel.AssertTCPConn(httpConn)
			if brw.Reader.Buffered() > 0 {
				log.Warn().Msg("client sent data prematurely")
				brw.WriteTo(sshTcpConn)
			}
			go func() {
				defer sshConn.Close()
				readAmt, err := httpTcpConn.WriteTo(sshTcpConn)
				if err != nil {
					log.Error().Err(err).Msg("copy to ssh")
				}
				log.Debug().Int64("bytes_read", readAmt).Msg("read finished")
			}()
			// FIXME: ssh connection remains open in certain conditions.
			// One fix is to close `sshConn` above. Granted, this creates
			// a "use of closed network connection"  error.
			// Maybe there's a better way?
			writeAmt, err := httpTcpConn.ReadFrom(sshTcpConn)
			if err != nil && !errors.Is(err, net.ErrClosed) {
				log.Error().Err(err).Msg("copy to http")
			}
			log.Debug().Int64("bytes_written", writeAmt).Msg("write finished")
		}
	}
}
