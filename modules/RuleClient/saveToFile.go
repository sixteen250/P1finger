package RuleClient

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/projectdiscovery/gologger"
	"github.com/xuri/excelize/v2"
)

func SaveToFile(DetectResult []DetectResult, output string) (err error) {
	// outputType := strings.Split(output, ".")[1]
	// 使用 filepath.Ext() 获取扩展名，并去掉前面的点
	outputType := strings.TrimPrefix(filepath.Ext(output), ".")

	// 转换为小写以确保匹配
	outputType = strings.ToLower(outputType)

	switch outputType {
	case "xlsx":
		err = SaveToExcel(DetectResult, output)
		if err != nil {
			return err
		}
		gologger.Info().Msgf("Data has been written to %v", output)
	case "json":
		var jsonData []byte
		jsonData, err = json.MarshalIndent(DetectResult, "", "  ")
		if err != nil {
			gologger.Error().Msgf("Error marshaling JSON:", err)
			return
		}

		file, err := os.Create(output)
		if err != nil {
			return fmt.Errorf("error creating file: %v", err)
		}
		defer file.Close()

		_, err = file.Write(jsonData)
		if err != nil {
			return fmt.Errorf("error writing to file: %v", err)
		}

		gologger.Info().Msgf("Data has been written to %v", output)
	}
	return
}

func SaveToExcel(targetFingerRsts []DetectResult, outputFile string) error { // 创建新的 Excel 文件
	f := excelize.NewFile()

	sheetName := "P1fingerSheet1"
	index, _ := f.NewSheet(sheetName)

	headers := []string{"host", "Target URL", "Web Title", "Site Up", "Finger Tags", "Last Update Time"}
	for col, header := range headers {
		cell := fmt.Sprintf("%s1", string('A'+col)) // A1, B1, C1, D1
		f.SetCellValue(sheetName, cell, header)
	}

	columnWidths := []float64{50, 40, 50, 20, 90, 40} // 根据需要调整列宽
	for i, width := range columnWidths {
		if err := f.SetColWidth(sheetName, string('A'+i), string('A'+i), width); err != nil {
			return err
		}
	}

	for row, target := range targetFingerRsts {
		f.SetCellValue(sheetName, fmt.Sprintf("A%d", row+2), target.Host)
		f.SetCellValue(sheetName, fmt.Sprintf("B%d", row+2), target.OriginUrl)
		f.SetCellValue(sheetName, fmt.Sprintf("C%d", row+2), target.WebTitle)
		f.SetCellValue(sheetName, fmt.Sprintf("D%d", row+2), target.SiteUp)
		f.SetCellValue(sheetName, fmt.Sprintf("E%d", row+2), strings.Join(target.FingerTag, ", "))
		f.SetCellValue(sheetName, fmt.Sprintf("F%d", row+2), target.LastUpdateTime)
	}

	f.SetActiveSheet(index)
	if err := f.SaveAs(outputFile); err != nil {
		return err
	}

	return nil
}
