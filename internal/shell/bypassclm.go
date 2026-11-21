package shell

import (
	"context"
	_ "embed"
	"fmt"
	"math/rand"
	"os"
	"strings"
	"time"

	"github.com/sresarehumantoo/wsmancer/internal/output"
)

//go:embed assets/bypass-clm.ps1.tmpl
var bypassCLMTemplate string

const bypassCLMFuncCount = 2
const bypassCLMVarCount = 16

func (sh *Shell) bypassCLM(ctx context.Context, sigs <-chan os.Signal) error {
	if sh.clmBypassed {
		if !sh.json && !sh.quiet {
			fmt.Fprintf(sh.out, "%s CLM is already bypassed in this runspace\n", sh.c.Blue("Info:"))
		}
		return nil
	}

	script := obfuscateBypass(bypassCLMTemplate, bypassCLMFuncCount, bypassCLMVarCount, rand.New(rand.NewSource(cryptoSeed())))
	steps := strings.Split(script, jumpMarker)

	if !sh.json && !sh.quiet {
		fmt.Fprintf(sh.out, "%s bypassing CLM in %d steps (~%s)...\n",
			sh.c.Blue("Info:"), len(steps), (time.Duration(len(steps)-1) * bypassStepPause).Round(time.Second))
	}

	for i, step := range steps {
		if strings.TrimSpace(step) == "" {
			continue
		}
		res, err := sh.s.RunRaw(ctx, step)
		if err != nil {
			return fmt.Errorf("step %d/%d: %w", i+1, len(steps), err)
		}
		if len(res.Errors) > 0 {
			return fmt.Errorf("step %d/%d: %s", i+1, len(steps),
				sanitizeTerminal(output.Text(res.Errors[0])))
		}
		for _, v := range res.Output {
			if s := strings.TrimSpace(output.Text(v)); s != "" {
				return fmt.Errorf("step %d/%d: %s", i+1, len(steps), sanitizeTerminal(s))
			}
		}
		if i == len(steps)-1 {
			break
		}
		select {
		case <-sigs:
			if !sh.json {
				fmt.Fprintln(sh.out, sh.c.Yellow("^C (canceled part-way; CLM is NOT bypassed)"))
			}
			return errPayloadCancelled
		case <-time.After(bypassStepPause):
		}
	}

	sh.clmBypassed = true
	sh.log.Event("[bypass-clm] GetSystemLockdownPolicy patched")
	if !sh.json && !sh.quiet {
		fmt.Fprintf(sh.out, "%s CLM bypassed (FullLanguage)\n", sh.c.Blue("Info:"))
	}
	return nil
}
