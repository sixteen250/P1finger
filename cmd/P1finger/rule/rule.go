package rule

import (
	"fmt"
	"sync"
	"time"

	"github.com/P001water/P1finger/cmd"
	"github.com/P001water/P1finger/cmd/vars"
	"github.com/P001water/P1finger/libs/fileutils"
	"github.com/P001water/P1finger/modules/RuleClient"
	"github.com/P001water/P1finger/modules/p1fmt"
	"github.com/fatih/color"
	"github.com/k0kubun/go-ansi"
	"github.com/projectdiscovery/gologger"
	"github.com/schollz/progressbar/v3"
	"github.com/spf13/cobra"
)

func init() {
	cmd.RootCmd.AddCommand(RuleCmd)

	RuleCmd.Flags().StringVarP(&vars.Options.Url, "url", "u", "", "target url")
	RuleCmd.Flags().StringVarP(&vars.Options.UrlFile, "file", "f", "", "target url file")
	RuleCmd.Flags().IntVarP(&vars.Options.Rate, "rate", "r", 500, "The number of go coroutines")
}

var RuleCmd = &cobra.Command{
	Use:   "rule",
	Short: "基于P1finger本地指纹库的指纹识别",
	PreRun: func(cmd *cobra.Command, args []string) {

	},
	Run: func(cmd *cobra.Command, args []string) {
		err := RuleRun()
		if err != nil {
			gologger.Error().Msg(err.Error())
			return
		}
	},
}

func RuleRun() (err error) {

	p1ruleClient, err := RuleClient.NewRuleClientBuilder().
		WithProxyURL(vars.Options.ProxyUrl).
		WithCustomizeFingerFile(vars.AppConf.CustomizeFingerFiles).
		WithDefaultFingerFiles(vars.AppConf.UseDefaultFingerFiles).
		WithOutputFormat(vars.Options.Output).
		WithTimeout(10 * time.Second).
		Build()
	if err != nil {
		gologger.Error().Msgf("%v", err)
	}

	// 整合目标输入
	var targetUrls []string
	if vars.Options.Url != "" {
		targetUrls = append(targetUrls, vars.Options.Url)
	}

	if vars.Options.UrlFile != "" {
		var urlsFromFile []string
		// filePath := filepath.Join(vars.ExecDir, vars.Options.UrlFile)
		filePath := vars.Options.UrlFile
		urlsFromFile, err = fileutils.ReadLinesFromFile(filePath)
		if err != nil {
			gologger.Error().Msgf("%v", err)
			return
		}
		targetUrls = append(targetUrls, urlsFromFile...)
	}

	if len(targetUrls) <= 0 {
		gologger.Error().Msg("input url is null")
		return
	}

	bar := progressbar.NewOptions(len(targetUrls),
		progressbar.OptionSetWriter(ansi.NewAnsiStdout()),
		progressbar.OptionEnableColorCodes(true),
		progressbar.OptionShowBytes(true),
		progressbar.OptionSetWidth(30),
		progressbar.OptionSetDescription("[cyan][P1finger][reset] 检测进度..."),
		progressbar.OptionSetTheme(progressbar.Theme{
			Saucer:        "[green]=[reset]",
			SaucerHead:    "[green]>[reset]",
			SaucerPadding: " ",
			BarStart:      "[",
			BarEnd:        "]",
		}))

	var workWg sync.WaitGroup
	concurrency := vars.Options.Rate
	urlChan := make(chan string, len(targetUrls))

	// 启动固定数量的 worker
	for i := 0; i < concurrency; i++ {
		go func() {
			for url := range urlChan {
				defer workWg.Done()
				_, _ = p1ruleClient.Detect(url)
				bar.Add(1)
			}
		}()
	}

	// 发送任务到 channel
	for _, url := range targetUrls {
		workWg.Add(1)
		urlChan <- url
	}

	close(urlChan)
	workWg.Wait()
	bar.Finish()
	fmt.Println()

	for _, shoot := range p1ruleClient.RstShoot.GetElements() {
		prefix := color.New(color.FgGreen).Add(color.Bold).Sprintf("[已命中]")
		// P1finger的指纹还在清洗阶段，区分生产和测试模式，清洗指纹
		if vars.Options.Debug {
			p1fmt.PrintfShoot(prefix, shoot.OriginUrl, shoot.WebTitle, shoot.FingerTag, shoot.OriginUrlStatusCode)
		} else {
			p1fmt.PrintfShoot(prefix, shoot.OriginUrl, shoot.WebTitle, RuleClient.SliceRmDuplication(shoot.FingerTag), shoot.OriginUrlStatusCode)
		}

	}

	for _, miss := range p1ruleClient.RstMiss.GetElements() {
		prefix := color.New(color.FgRed).Add(color.Bold).Sprintf("[未命中]")
		if vars.Options.Debug {
			p1fmt.PrintMiss(prefix, miss.OriginUrl, miss.WebTitle, miss.FingerTag, miss.OriginUrlStatusCode)
		} else {
			p1fmt.PrintMiss(prefix, miss.OriginUrl, miss.WebTitle, RuleClient.SliceRmDuplication(miss.FingerTag), miss.OriginUrlStatusCode)
		}
	}

	for _, reqFail := range p1ruleClient.RstReqFail.GetElements() {
		prefix := color.New(color.FgBlue).Add(color.Bold).Sprintf("[无法访问]")

		if vars.Options.Debug {
			p1fmt.PrintReqFail(prefix, reqFail.OriginUrl, reqFail.FingerTag)
		} else {
			p1fmt.PrintReqFail(prefix, reqFail.OriginUrl, RuleClient.SliceRmDuplication(reqFail.FingerTag))
		}
	}

	err = RuleClient.SaveToFile(p1ruleClient.DetectRstTdSafe.GetElements(), p1ruleClient.OutputFormat)
	if err != nil {
		gologger.Error().Msg(err.Error())
		return
	}

	return

}
