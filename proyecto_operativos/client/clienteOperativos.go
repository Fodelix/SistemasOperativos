// clienteOperativos.go - Módulo Windows (cliente)
// Uso: clienteOperativos <IP> <Puerto> <PeriodoReporte>
// Ej:  clienteOperativos 10.1.10.3 2306 5
// Compilar para Windows: GOOS=windows GOARCH=amd64 go build -o clienteOperativos.exe ./client
package main

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"golang.org/x/term"
)

func main() {
	if len(os.Args) != 4 {
		fmt.Println("Uso: clienteOperativos <IP> <Puerto> <PeriodoReporte>")
		os.Exit(1)
	}
	ip, puerto := os.Args[1], os.Args[2]
	periodo, err := strconv.Atoi(os.Args[3])
	if err != nil || periodo <= 0 {
		fmt.Println("PeriodoReporte debe ser un entero > 0")
		os.Exit(1)
	}
	conn, err := net.Dial("tcp4", net.JoinHostPort(ip, puerto))
	if err != nil {
		fmt.Println("No se pudo conectar:", err)
		os.Exit(1)
	}
	defer conn.Close()
	fmt.Println("Conectado al server", conn.RemoteAddr())

	r := bufio.NewReader(conn)
	w := bufio.NewWriter(conn)
	stdin := bufio.NewReader(os.Stdin)
	enviar := func(s string) { w.WriteString(s + "\n"); w.Flush() }

	// ---- Autenticación ----
	autenticado := false
	for !autenticado {
		fmt.Print("Usuario: ")
		u, _ := stdin.ReadString('\n')
		u = strings.TrimSpace(u)
		fmt.Print("Password: ")
		pb, _ := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Println()
		enviar("LOGIN|" + u + "|" + string(pb))

		resp, err := r.ReadString('\n')
		if err != nil {
			fmt.Println("Conexión cerrada por el servidor.")
			return
		}
		resp = strings.TrimRight(resp, "\r\n")
		switch {
		case resp == "AUTH|OK":
			fmt.Println("------ LOGIN CORRECTO ------")
			autenticado = true
		case strings.HasPrefix(resp, "AUTH|FAIL|"):
			fmt.Println("Credenciales incorrectas. Intentos restantes:", strings.TrimPrefix(resp, "AUTH|FAIL|"))
		case resp == "AUTH|BLOCKED":
			fmt.Println("Demasiados intentos fallidos. Conexión cerrada.")
			return
		default:
			fmt.Println("Servidor:", strings.TrimPrefix(resp, "ERR|"))
			return
		}
	}

	enviar("PERIOD|" + strconv.Itoa(periodo))
	fin := make(chan struct{})
	listo := make(chan struct{}, 1) // el servidor terminó de enviar la salida de un comando

	// ---- Hilo receptor: reportes y salida de comandos, en paralelo ----
	go func() {
		defer close(fin)
		for {
			l, err := r.ReadString('\n')
			if err != nil {
				return
			}
			l = strings.TrimRight(l, "\r\n")
			switch {
			case strings.HasPrefix(l, "REP|"):
				fmt.Printf("\n[REPORTE %s] %s\n", time.Now().Format("15:04:05"), l[4:])
			case strings.HasPrefix(l, "OUT|"):
				fmt.Println(l[4:])
			case l == "END|":
				select {
				case listo <- struct{}{}:
				default:
				}
			case l == "BYE|":
				return
			}
		}
	}()

	// ---- Shell remoto ----
	for {
		fmt.Print("oper% ")
		cmd, err := stdin.ReadString('\n')
		if err != nil {
			enviar("bye")
			return
		}
		cmd = strings.TrimSpace(cmd)
		if cmd == "" {
			continue
		}
		if cmd == "bye" {
			enviar("bye")
			select {
			case <-fin:
			case <-time.After(2 * time.Second):
			}
			fmt.Println("Sesión finalizada.")
			return
		}
		enviar("CMD|" + cmd)
		select {
		case <-listo:
		case <-fin:
			fmt.Println("Conexión cerrada por el servidor.")
			return
		}
	}
}
