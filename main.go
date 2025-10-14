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
		Status string `json:"status"`
		Ref    string `json:"ref"`
		URL    string `json:"url"`
	} `json:"object_attributes"`
	Project struct {
		Path              string `json:"path"`
		PathWithNamespace string `json:"path_with_namespace"`
		Name              string `json:"name"`
		WebURL            string `json:"web_url"`
	} `json:"project"`
	User struct {
		Name string `json:"name"`
	} `json:"user"`
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

	// 🧾 Логируем конфигурацию
	log.Println("--------------------------------------------------")
	log.Println("[INFO] Конфигурация успешно загружена")
	log.Printf("[INFO] Порт: %d", cfg.Port)
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
		log.Println("[INFO] Проектов в конфиге нет")
	} else {
		log.Println("[INFO] Настройки по проектам:")
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
		log.Fatalf("[FATAL] Не удалось загрузить конфиг: %v", err)
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
			log.Printf("[WARN] Отказано в доступе: неверный X-Gitlab-Token от %s", r.RemoteAddr)
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

		// Обрабатываем только pipeline-события
		if payload.ObjectKind != "pipeline" {
			log.Printf("[INFO] Игнорируется webhook с типом '%s'", payload.ObjectKind)
			w.WriteHeader(http.StatusOK)
			return
		}

		// Извлекаем проект
		project := payload.Project.Path
		if project == "" {
			project = payload.Project.PathWithNamespace
		}
		if project == "" {
			project = payload.Project.Name
		}
		project = filepath.Base(project)

		status := payload.ObjectAttributes.Status
		ref := payload.ObjectAttributes.Ref
		url := payload.ObjectAttributes.URL
		user := payload.User.Name

		if project == "" || status != "success" {
			log.Printf("[INFO] Игнорируется webhook (project=%s, status=%s)", project, status)
			w.WriteHeader(http.StatusOK)
			return
		}

		log.Printf("[INFO] Получен успешный pipeline: project=%s, branch=%s, user=%s, url=%s", project, ref, user, url)

		// Формируем путь до скрипта
		script := filepath.Join(scriptsDir, fmt.Sprintf("%s.sh", project))
		if _, err := os.Stat(script); os.IsNotExist(err) {
			msg := fmt.Sprintf("Нет скрипта для проекта '%s'", project)
			log.Println(msg)
			sendTelegram(project, fmt.Sprintf("❌ %s", msg))
			http.Error(w, msg, http.StatusNotFound)
			return
		}

		// Отправляем уведомление о старте
		startMsg := fmt.Sprintf("🚀 *Запуск деплоя*\nПроект: `%s`\nВетка: `%s`\nАвтор: %s\n[Открыть Pipeline](%s)",
			project, ref, user, url)
		sendTelegram(project, startMsg)

		cmd := exec.Command("bash", script)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr

		if err := cmd.Run(); err != nil {
			msg := fmt.Sprintf("❌ Ошибка при выполнении скрипта '%s': %v", project, err)
			log.Println(msg)
			sendTelegram(project, msg)
			http.Error(w, msg, http.StatusInternalServerError)
			return
		}

		doneMsg := fmt.Sprintf("✅ *Деплой завершён*\nПроект: `%s`\nВетка: `%s`\n[Pipeline](%s)", project, ref, url)
		sendTelegram(project, doneMsg)
		log.Printf("[INFO] Скрипт для %s выполнен успешно", project)
		w.WriteHeader(http.StatusOK)
	})

	// === Эндпоинт для перезагрузки конфига ===
	http.HandleFunc("/reload", func(w http.ResponseWriter, r *http.Request) {
		if !checkRequestToken(r) {
			log.Printf("[WARN] Отказано в доступе к /reload: неверный X-Gitlab-Token от %s", r.RemoteAddr)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		if r.Method != http.MethodPost {
			http.Error(w, "Use POST", http.StatusMethodNotAllowed)
			return
		}

		if err := loadConfig(configFile); err != nil {
			log.Printf("[ERROR] Перезагрузка конфига не удалась: %v", err)
			http.Error(w, fmt.Sprintf("Reload failed: %v", err), http.StatusInternalServerError)
			return
		}

		log.Println("[INFO] Конфиг успешно перезагружен по запросу /reload")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Config reloaded successfully\n"))
	})

	addr := fmt.Sprintf(":%d", port)
	log.Printf("[INFO] Сервис запущен, слушает %s", addr)
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
		log.Printf("[WARN] Telegram config missing for %s", project)
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
}
