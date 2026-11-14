// serverOper.go - Módulo Linux (servidor)
// Compilar: go build -o serverOper ./server
// Ejecutar: ./serverOper oper.conf
package main

import (
	"bufio"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

// ---------- Configuración (.conf) ----------
type Config struct {
	IPPermitida  string
	Puerto       string
	MaxIntentos  int
	ArchivoUsers string
	Usuarios     map[string]bool
}

func leerConfig(nom string) (*Config, error) {
	datos, err := os.ReadFile(nom)
	if err != nil {
		return nil, err
	}
	c := &Config{Puerto: "2306", MaxIntentos: 3, ArchivoUsers: "oper.users.db", Usuarios: map[string]bool{}}
	for _, l := range strings.Split(string(datos), "\n") {
		l = strings.TrimSpace(l)
		if l == "" || strings.HasPrefix(l, "#") {
			continue
		}
		kv := strings.SplitN(l, "=", 2)
		if len(kv) != 2 {
			continue
		}
		k, v := strings.TrimSpace(kv[0]), strings.TrimSpace(kv[1])
		switch k {
		case "ip_permitida":
			c.IPPermitida = v
		case "puerto":
			c.Puerto = v
		case "intentos_max":
			if n, e := strconv.Atoi(v); e == nil && n > 0 {
				c.MaxIntentos = n
			}
		case "archivo_usuarios":
			c.ArchivoUsers = v
		case "usuarios_permitidos":
			for _, u := range strings.Split(v, ",") {
				if u = strings.TrimSpace(u); u != "" {
					c.Usuarios[u] = true
				}
			}
		}
	}
	return c, nil
}

// ---------- Base de usuarios (archivo plano usuario:hashSHA256) ----------
func cargarUsuarios(nom string) map[string]string {
	db := map[string]string{}
	datos, err := os.ReadFile(nom)
	if err != nil {
		return db
	}
	for _, l := range strings.Split(string(datos), "\n") {
		cred := strings.SplitN(strings.TrimSpace(l), ":", 2)
		if len(cred) == 2 {
			db[cred[0]] = strings.ToLower(cred[1])
		}
	}
	return db
}

func (c *Config) valida(u, p string) bool {
	if !c.Usuarios[u] {
		return false
	}
	h, ok := cargarUsuarios(c.ArchivoUsers)[u]
	if !ok {
		return false
	}
	hp := fmt.Sprintf("%x", sha256.Sum256([]byte(p)))
	return subtle.ConstantTimeCompare([]byte(hp), []byte(h)) == 1
}

// ---------- Sesión (escritura protegida: comandos y reportes en paralelo) ----------
type sesion struct {
	w  *bufio.Writer
	mu sync.Mutex
}

func (s *sesion) enviar(lineas ...string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, l := range lineas {
		s.w.WriteString(l + "\n")
	}
	s.w.Flush()
}

func main() {
	archConf := "oper.conf"
	if len(os.Args) > 1 {
		archConf = os.Args[1]
	}
	conf, err := leerConfig(archConf)
	if err != nil {
		fmt.Println("No se pudo leer", archConf, ":", err)
		os.Exit(1)
	}
	ln, err := net.Listen("tcp4", ":"+conf.Puerto)
	if err != nil {
		fmt.Println("Error abriendo socket:", err)
		os.Exit(1)
	}
	fmt.Println("Servidor escuchando en puerto", conf.Puerto)
	for {
		conn, err := ln.Accept()
		if err != nil {
			continue
		}
		go atender(conn, conf)
	}
}

func atender(conn net.Conn, conf *Config) {
	defer conn.Close()
	s := &sesion{w: bufio.NewWriter(conn)}
	host, _, _ := net.SplitHostPort(conn.RemoteAddr().String())
	fmt.Println("Conexión desde", host)
	if conf.IPPermitida != "" && conf.IPPermitida != "*" && host != conf.IPPermitida {
		s.enviar("ERR|IP no permitida")
		fmt.Println("Rechazada IP no permitida:", host)
		return
	}
	r := bufio.NewReader(conn)
	if !autenticar(r, s, conf) {
		fmt.Println("Autenticación fallida desde", host)
		return
	}
	fmt.Println("Usuario autenticado desde", host)

	var periodo atomic.Int64
	done := make(chan struct{})
	defer close(done)
	go reportar(s, &periodo, done)

	for {
		l, err := r.ReadString('\n')
		if err != nil {
			return
		}
		l = strings.TrimRight(l, "\r\n")
		switch {
		case l == "bye":
			s.enviar("BYE|")
			return
		case strings.HasPrefix(l, "PERIOD|"):
			if n, e := strconv.Atoi(l[7:]); e == nil && n > 0 {
				periodo.Store(int64(n))
			}
		case strings.HasPrefix(l, "CMD|"):
			ejecutar(s, l[4:])
		}
	}
}

func autenticar(r *bufio.Reader, s *sesion, conf *Config) bool {
	for i := 1; i <= conf.MaxIntentos; i++ {
		l, err := r.ReadString('\n')
		if err != nil {
			return false
		}
		p := strings.SplitN(strings.TrimRight(l, "\r\n"), "|", 3)
		if len(p) == 3 && p[0] == "LOGIN" && conf.valida(p[1], p[2]) {
			s.enviar("AUTH|OK")
			return true
		}
		time.Sleep(time.Duration(i) * 500 * time.Millisecond) // retardo creciente (Lab login.go)
		if i == conf.MaxIntentos {
			s.enviar("AUTH|BLOCKED")
			return false
		}
		s.enviar(fmt.Sprintf("AUTH|FAIL|%d", conf.MaxIntentos-i))
	}
	return false
}

// ---------- Ejecución de comandos (Lab shell.go) ----------
func ejecutar(s *sesion, comando string) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "bash", "-c", comando).CombinedOutput()
	txt := strings.TrimRight(string(out), "\r\n")
	var lineas []string
	if txt != "" {
		for _, l := range strings.Split(txt, "\n") {
			lineas = append(lineas, "OUT|"+l)
		}
	}
	if ctx.Err() == context.DeadlineExceeded {
		lineas = append(lineas, "OUT|[tiempo de ejecución excedido: 30 s]")
	} else if err != nil && txt == "" {
		lineas = append(lineas, "OUT|[error: "+err.Error()+"]")
	}
	lineas = append(lineas, "END|")
	s.enviar(lineas...)
}

// ---------- Reporte de recursos cada n segundos ----------
func reportar(s *sesion, periodo *atomic.Int64, done chan struct{}) {
	for {
		espera := time.Second
		if p := periodo.Load(); p > 0 {
			espera = time.Duration(p) * time.Second
		}
		select {
		case <-done:
			return
		case <-time.After(espera):
		}
		if periodo.Load() > 0 {
			s.enviar("REP|" + generarReporte())
		}
	}
}

func leerCPU() (idle, total uint64) {
	datos, err := os.ReadFile("/proc/stat")
	if err != nil {
		return
	}
	campos := strings.Fields(strings.SplitN(string(datos), "\n", 2)[0])
	for i, c := range campos[1:] {
		v, _ := strconv.ParseUint(c, 10, 64)
		total += v
		if i == 3 || i == 4 { // idle + iowait
			idle += v
		}
	}
	return
}

func generarReporte() string {
	i1, t1 := leerCPU()
	time.Sleep(500 * time.Millisecond)
	i2, t2 := leerCPU()
	cpu := 0.0
	if t2 > t1 {
		cpu = 100 * (1 - float64(i2-i1)/float64(t2-t1))
	}

	var memTot, memDisp float64
	if datos, err := os.ReadFile("/proc/meminfo"); err == nil {
		for _, l := range strings.Split(string(datos), "\n") {
			f := strings.Fields(l)
			if len(f) < 2 {
				continue
			}
			v, _ := strconv.ParseFloat(f[1], 64)
			switch f[0] {
			case "MemTotal:":
				memTot = v / 1024
			case "MemAvailable:":
				memDisp = v / 1024
			}
		}
	}
	memUso := memTot - memDisp
	memPct := 0.0
	if memTot > 0 {
		memPct = 100 * memUso / memTot
	}

	procs := 0
	if ents, err := os.ReadDir("/proc"); err == nil {
		for _, e := range ents {
			if _, err := strconv.Atoi(e.Name()); err == nil {
				procs++
			}
		}
	}

	var st syscall.Statfs_t
	ddTot, ddUso, ddPct := 0.0, 0.0, 0.0
	if syscall.Statfs("/", &st) == nil {
		ddTot = float64(st.Blocks) * float64(st.Bsize) / 1e9
		ddUso = ddTot - float64(st.Bavail)*float64(st.Bsize)/1e9
		if ddTot > 0 {
			ddPct = 100 * ddUso / ddTot
		}
	}
	return fmt.Sprintf("CPU=%.1f%% | PROC=%d | RAM=%.1f%% (%.0f/%.0f MB) | DD=%.1f%% (%.1f/%.1f GB)",
		cpu, procs, memPct, memUso, memTot, ddPct, ddUso, ddTot)
}
