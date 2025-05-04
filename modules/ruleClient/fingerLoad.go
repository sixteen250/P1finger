package ruleClient

import (
	"embed"
	"fmt"
	"gopkg.in/yaml.v3"
	"os"
	"path/filepath"
)

//go:embed P1fingersYaml/*
var ExeFs embed.FS

func (r *RuleClient) LoadFingersFromFile(exeDir string, fingerFiles []string) (err error) {

	for _, file := range fingerFiles {
		filePath := filepath.Join(exeDir, file)
		fileInf, err := os.Stat(filePath)
		if err != nil {
			return fmt.Errorf("❌ File %s not existing:", file)
		}

		if filepath.Ext(file) == ".yaml" {
			fileBytes, err := os.ReadFile(filePath)
			if err != nil {
				return fmt.Errorf("❌ 无法读取文件:", fileInf.Name(), err)
			}

			var newFingerprints []FingerprintsType
			err = yaml.Unmarshal(fileBytes, &newFingerprints)
			if err != nil {
				return fmt.Errorf("❌ 解析 YAML 失败:", fileInf.Name(), err)
			}

			for _, fingerprint := range newFingerprints {
				fingerprint.FingerFile = filepath.Base(fileInf.Name())
			}

			r.P1FingerPrints.FingerSlice = append(r.P1FingerPrints.FingerSlice, newFingerprints...)
		}
	}

	return nil
}

func (r *RuleClient) LoadFingersFromExEfs() (err error) {

	fingerfolderPath := r.DefaultFingerPath

	ExeFsFingerFiles, err := ExeFs.ReadDir(fingerfolderPath)
	if err != nil {
		return fmt.Errorf("❌ 无法打开嵌入文件夹:", err)
	}

	for _, file := range ExeFsFingerFiles {
		if filepath.Ext(file.Name()) == ".yaml" {
			fileBytes, err := ExeFs.ReadFile(fingerfolderPath + "/" + file.Name())
			if err != nil {
				return fmt.Errorf("❌ 无法读取文件:", file.Name(), err)
			}

			var newFingerprints []FingerprintsType
			err = yaml.Unmarshal(fileBytes, &newFingerprints)
			if err != nil {
				return fmt.Errorf("❌ 解析 YAML 失败:", file.Name(), err)
			}

			for i := range newFingerprints {
				newFingerprints[i].FingerFile = file.Name()
			}

			r.P1FingerPrints.FingerSlice = append(r.P1FingerPrints.FingerSlice, newFingerprints...)
		}
	}
	return nil
}
