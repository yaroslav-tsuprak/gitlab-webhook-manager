package main

import (
	"bytes"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sync"

	"gopkg.in/yaml.v3"
)

// TelegramConfig описывает конфигурацию Telegram
type TelegramConfig struct {
	Enabled bool   `yaml:"enabled"`
	Token   string `yaml:"token"`
	ChatID  string `yaml:"chat_id"`
}

// ProjectConfig описывает настройки конкретного проекта
type ProjectConfig struct {
	Telegram TelegramConfig `yaml:"telegram"`
}

// Config описывает всю конфигурацию сервиса
type Config struct {
	Port        int                      `yaml:"port"`
	SecretToken string                   `yaml:"secret_token"`
	Telegram    TelegramConfig           `yaml:"telegram"`
	Projects    map[string]ProjectConfig `yaml:"projects"`
}

// WebhookPayload структура GitLab webhook (pipeline)
type WebhookPayload struct {
	ObjectKind       string `json:"object_kind"`
	ObjectAttributes struct {
		ID             int      `json:"id"`
		Status         string   `json:"status"`
		Ref            string   `json:"ref"`
		URL            string   `json:"url"`
		Source         string   `json:"source"`
		CreatedAt      string   `json:"created_at"`
		FinishedAt     string   `json:"finished_at"`
		Duration       float64  `json:"duration"`
		QueuedDuration float64  `json:"queued_duration"`
		Stages         []string `json:"stages"`
	} `json:"object_attributes"`

	User struct {
		Name     string `json:"name"`
		Username string `json:"username"`
		Email    string `json:"email"`
	} `json:"user"`

	Project struct {
		ID                int    `json:"id"`
		Name              string `json:"name"`
		Path              string `json:"path"`
		PathWithNamespace string `json:"path_with_namespace"`
		WebURL            string `json:"web_url"`
		Namespace         string `json:"namespace"`
	} `json:"project"`

	Commit struct {
		ID      string `json:"id"`
		Message string `json:"message"`
		URL     string `json:"url"`
		Author  struct {
			Name  string `json:"name"`
			Email string `json:"email"`
		} `json:"author"`
	} `json:"commit"`

	Builds []struct {
		ID         int     `json:"id"`
		Stage      string  `json:"stage"`
		Name       string  `json:"name"`
		Status     string  `json:"status"`
		Duration   float64 `json:"duration"`
		StartedAt  string  `json:"started_at"`
		FinishedAt string  `json:"finished_at"`
	} `json:"builds"`
}

// Глобальные переменные
var (
	cfg     Config
	cfgLock sync.RWMutex
)

// loadConfig загружает конфигурацию из YAML-файла
func loadConfig(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open config: %w", err)
	}
	defer f.Close()

	data, err := io.ReadAll(f)
	if err != nil {
		return fmt.Errorf("read config: %w", err)
	}

	var newCfg Config
	if err := yaml.Unmarshal(data, &newCfg); err != nil {
		return fmt.Errorf("parse config: %w", err)
	}

	cfgLock.Lock()
	cfg = newCfg
	cfgLock.Unlock()

	log.Println("--------------------------------------------------")
	log.Println("[INFO] Config successfully loaded")
	log.Printf("[INFO] Port: %d", cfg.Port)
	if cfg.SecretToken != "" {
		if os.Getenv("SHOW_SECRET") == "true" {
			log.Printf("[INFO] Secret token: %s", cfg.SecretToken)
		} else {
			log.Printf("[INFO] Secret token: configured (hidden)")
		}
	} else {
		log.Printf("[INFO] Secret token: not configured (open mode)")
	}
	log.Printf("[INFO] Telegram: enabled=%v, chat_id=%s", cfg.Telegram.Enabled, cfg.Telegram.ChatID)

	if len(cfg.Projects) == 0 {
		log.Println("[INFO] No per-project configs found")
	} else {
		log.Println("[INFO] Project overrides:")
		for name, prj := range cfg.Projects {
			log.Printf("  - %s: telegram.enabled=%v, chat_id=%s",
				name, prj.Telegram.Enabled, prj.Telegram.ChatID)
		}
	}
	log.Println("--------------------------------------------------")

	return nil
}

// checkRequestToken проверяет X-Gitlab-Token
func checkRequestToken(r *http.Request) bool {
	cfgLock.RLock()
	secret := cfg.SecretToken
	cfgLock.RUnlock()

	if secret == "" {
		return true
	}

	token := r.Header.Get("X-Gitlab-Token")
	if token == "" {
		return false
	}

	return subtle.ConstantTimeCompare([]byte(token), []byte(secret)) == 1
}

func main() {
	configFile := os.Getenv("CONFIG_PATH")
	if configFile == "" {
		configFile = "/app/config/config.yaml"
	}

	if err := loadConfig(configFile); err != nil {
		log.Fatalf("[FATAL] Failed to load config: %v", err)
	}

	cfgLock.RLock()
	port := cfg.Port
	cfgLock.RUnlock()
	if port == 0 {
		port = 8080
	}

	scriptsDir := os.Getenv("SCRIPTS_DIR")
	if scriptsDir == "" {
		scriptsDir = "/app/scripts"
	}

	log.Println("--------------------------------------------------")
	log.Printf("[INFO] Using config file: %s", configFile)
	log.Printf("[INFO] Using scripts directory: %s", scriptsDir)
	log.Println("--------------------------------------------------")

	// === Основной webhook обработчик ===
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if !checkRequestToken(r) {
			log.Printf("[WARN] Unauthorized X-Gitlab-Token from %s", r.RemoteAddr)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		var payload WebhookPayload
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			http.Error(w, "Invalid JSON", http.StatusBadRequest)
			return
		}

		if payload.ObjectKind != "pipeline" {
			log.Printf("[INFO] Ignored webhook type '%s'", payload.ObjectKind)
			w.WriteHeader(http.StatusOK)
			return
		}

		project := filepath.Base(payload.Project.PathWithNamespace)
		if project == "" {
			project = payload.Project.Name
		}
		if project == "" {
			log.Printf("[INFO] Ignored webhook: empty project name")
			w.WriteHeader(http.StatusOK)
			return
		}

		status := payload.ObjectAttributes.Status
		ref := payload.ObjectAttributes.Ref
		url := payload.ObjectAttributes.URL
		user := payload.User.Name
		pipelineID := payload.ObjectAttributes.ID

		commitID := payload.Commit.ID
		commitMsg := payload.Commit.Message
		commitURL := payload.Commit.URL
		author := payload.Commit.Author.Name

		if status != "success" {
			log.Printf("[INFO] Ignored webhook (project=%s, status=%s)", project, status)
			w.WriteHeader(http.StatusOK)
			return
		}

		projectID := payload.Project.ID
		log.Printf("[INFO] Successful pipeline: project=%s (id=%d), pipeline_id=%d, branch=%s, user=%s",
			project, projectID, pipelineID, ref, user)

		// Формируем путь до скрипта: <project.name>-<project.id>.sh
		script := filepath.Join(scriptsDir, fmt.Sprintf("%s-%d.sh", project, projectID))
		if _, err := os.Stat(script); os.IsNotExist(err) {
			msg := fmt.Sprintf("❌ Script not found for `%s` (expected %s)", project, filepath.Base(script))
			log.Println(msg)
			sendTelegram(project, msg)
			http.Error(w, msg, http.StatusNotFound)
			return
		}

		// Уведомление о старте деплоя
		startMsg := fmt.Sprintf(
			"🚀 *Deploy started*\n"+
				"Project: `%s`\n"+
				"Project ID: `%d`\n"+
				"Pipeline ID: `%d`\n"+
				"Branch: `%s`\n"+
				"Commit: [`%.8s`](%s)\n"+
				"Message: _%s_\n"+
				"Author: %s\n"+
				"Triggered by: %s\n"+
				"[Open Pipeline →](%s)",
			project, projectID, pipelineID, ref, commitID, commitURL, commitMsg, author, user, url,
		)
		sendTelegram(project, startMsg)

		cmd := exec.Command("bash", script)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr

		if err := cmd.Run(); err != nil {
			msg := fmt.Sprintf("❌ Error while executing `%s`: %v", filepath.Base(script), err)
			log.Println(msg)
			sendTelegram(project, msg)
			http.Error(w, msg, http.StatusInternalServerError)
			return
		}

		doneMsg := fmt.Sprintf(
			"✅ *Deploy finished*\n"+
				"Project: `%s`\n"+
				"Project ID: `%d`\n"+
				"Branch: `%s`\n"+
				"Pipeline: [`%d`](%s)\n"+
				"Duration: `%.0f sec`\n"+
				"Commit: [`%.8s`](%s)",
			project, projectID, ref, pipelineID, url, payload.ObjectAttributes.Duration, commitID, commitURL,
		)
		sendTelegram(project, doneMsg)
		log.Printf("[INFO] Script %s executed successfully", filepath.Base(script))
		w.WriteHeader(http.StatusOK)
	})

	// === Эндпоинт для перезагрузки конфига ===
	http.HandleFunc("/reload", func(w http.ResponseWriter, r *http.Request) {
		if !checkRequestToken(r) {
			log.Printf("[WARN] Unauthorized access to /reload from %s", r.RemoteAddr)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		if r.Method != http.MethodPost {
			http.Error(w, "Use POST", http.StatusMethodNotAllowed)
			return
		}

		if err := loadConfig(configFile); err != nil {
			log.Printf("[ERROR] Config reload failed: %v", err)
			http.Error(w, fmt.Sprintf("Reload failed: %v", err), http.StatusInternalServerError)
			return
		}

		log.Println("[INFO] Config successfully reloaded via /reload")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Config reloaded successfully\n"))
	})

	// === Healthcheck ===
	http.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	})

	addr := fmt.Sprintf(":%d", port)
	log.Printf("[INFO] Service started on %s", addr)
	if err := http.ListenAndServe(addr, nil); err != nil {
		log.Fatal(err)
	}
}

// sendTelegram отправляет сообщение с учётом project-override
func sendTelegram(project, text string) {
	cfgLock.RLock()
	tcfg := cfg.Telegram
	if projCfg, ok := cfg.Projects[project]; ok {
		if projCfg.Telegram.Enabled {
			if projCfg.Telegram.Token != "" {
				tcfg.Token = projCfg.Telegram.Token
			}
			if projCfg.Telegram.ChatID != "" {
				tcfg.ChatID = projCfg.Telegram.ChatID
			}
			tcfg.Enabled = true
		} else {
			tcfg.Enabled = false
		}
	}
	cfgLock.RUnlock()

	if !tcfg.Enabled {
		return
	}

	if tcfg.Token == "" || tcfg.ChatID == "" {
		log.Printf("[WARN] Missing Telegram config for %s", project)
		return
	}

	url := fmt.Sprintf("https://api.telegram.org/bot%s/sendMessage", tcfg.Token)
	body := map[string]any{
		"chat_id":    tcfg.ChatID,
		"text":       text,
		"parse_mode": "Markdown",
	}
	b, _ := json.Marshal(body)

	resp, err := http.Post(url, "application/json", bytes.NewBuffer(b))
	if err != nil {
		log.Printf("[WARN] Telegram send failed: %v", err)
		return
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		log.Printf("[WARN] Telegram response %d: %s", resp.StatusCode, string(respBody))
	}
}
