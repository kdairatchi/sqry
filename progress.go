package main

import (
	"fmt"
	"os"
	"strings"
	"time"
)

type ProgressIndicator struct {
	message   string
	done      chan bool
	spinChars []string
	colors    []string
	startTime time.Time
}

type ProgressBar struct {
	total   int
	current int
	message string
	start   time.Time
}

func NewProgress(message string) *ProgressIndicator {
	p := &ProgressIndicator{
		message:   message,
		done:      make(chan bool),
		spinChars: []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"},
		colors:    []string{ColorCyan, ColorGreen, ColorYellow, ColorBlue, ColorPurple},
		startTime: time.Now(),
	}
	if !isTerminal() {
		return p // Don't start animation for non-terminal
	}
	p.startAnimation()
	return p
}

func NewProgressBar(total int, message string) *ProgressBar {
	return &ProgressBar{
		total:   total,
		current: 0,
		message: message,
		start:   time.Now(),
	}
}

func (p *ProgressIndicator) startAnimation() {
	go func() {
		ticker := time.NewTicker(120 * time.Millisecond)
		defer ticker.Stop()
		i := 0
		for {
			select {
			case <-p.done:
				fmt.Fprint(os.Stderr, "\r\033[K") // Clear the line
				return
			case <-ticker.C:
				elapsed := time.Since(p.startTime)
				colorIndex := (i / 10) % len(p.colors)
				spinner := p.spinChars[i%len(p.spinChars)]
				fmt.Fprintf(os.Stderr, "\r%s%s%s %s %s[%s]%s", 
					p.colors[colorIndex], spinner, ColorReset, 
					p.message, 
					ColorDim, elapsed.Round(time.Millisecond), ColorReset)
				i++
			}
		}
	}()
}

func (p *ProgressIndicator) Stop() {
	if !isTerminal() {
		return
	}
	close(p.done)
	fmt.Fprint(os.Stderr, "\r\033[K") // Clear the line
}

func (pb *ProgressBar) Update(current int) {
	if !isTerminal() {
		return
	}
	pb.current = current
	percent := float64(current) / float64(pb.total) * 100
	barWidth := 30
	filledWidth := int(float64(barWidth) * percent / 100)
	
	bar := strings.Repeat("█", filledWidth) + strings.Repeat("░", barWidth-filledWidth)
	elapsed := time.Since(pb.start)
	
	fmt.Fprintf(os.Stderr, "\r%s %s[%s] %s%.1f%%%s (%d/%d) %s[%s]%s",
		pb.message,
		ColorGreen, bar, ColorBold, percent, ColorReset,
		current, pb.total,
		ColorDim, elapsed.Round(time.Millisecond), ColorReset)
}

func (pb *ProgressBar) Finish() {
	if !isTerminal() {
		return
	}
	pb.Update(pb.total)
	fmt.Fprint(os.Stderr, "\n")
}