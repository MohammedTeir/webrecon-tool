package utils

import (
	"fmt"
	"log"
	"os"
	"time"

	"github.com/fatih/color"
)

// Logger represents a custom logger with colored output
type Logger struct {
	// Verbose mode
	Verbose bool
}

// NewLogger creates a new logger
func NewLogger(verbose bool) *Logger {
	return &Logger{
		Verbose: verbose,
	}
}

// Info logs an informational message
func (l *Logger) Info(format string, args ...interface{}) {
	color.Cyan("[INFO] "+format, args...)
}

// Success logs a success message
func (l *Logger) Success(format string, args ...interface{}) {
	color.Green("[SUCCESS] "+format, args...)
}

// Warning logs a warning message
func (l *Logger) Warning(format string, args ...interface{}) {
	color.Yellow("[WARNING] "+format, args...)
}

// Error logs an error message
func (l *Logger) Error(format string, args ...interface{}) {
	color.Red("[ERROR] "+format, args...)
}

// Debug logs a debug message (only in verbose mode)
func (l *Logger) Debug(format string, args ...interface{}) {
	if l.Verbose {
		color.Magenta("[DEBUG] "+format, args...)
	}
}

// Fatal logs an error message and exits
func (l *Logger) Fatal(format string, args ...interface{}) {
	color.Red("[FATAL] "+format, args...)
	os.Exit(1)
}

// LogToFile logs a message to a file
func (l *Logger) LogToFile(file, format string, args ...interface{}) error {
	f, err := os.OpenFile(file, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer f.Close()

	timestamp := time.Now().Format("2006-01-02 15:04:05")
	message := fmt.Sprintf(format, args...)
	_, err = fmt.Fprintf(f, "[%s] %s\n", timestamp, message)
	return err
}

// SetupFileLogger sets up a file logger
func SetupFileLogger(file string) *log.Logger {
	f, err := os.OpenFile(file, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Fatalf("Failed to open log file: %v", err)
	}

	return log.New(f, "", log.LstdFlags)
}
