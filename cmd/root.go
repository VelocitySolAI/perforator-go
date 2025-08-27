package cmd

import (
	"fmt"
	"os"

	"github.com/fatih/color"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var (
	cfgFile string
	verbose bool
	workers int
	timeout int
	output  string
)

const banner = `
 ____  _____ ____  _____ ____  ____  ____ _____ ____  ____    ____  ____  
/  __\/  __//  __\/    //  _ \/  __\/  _ Y__ __Y  _ \/  __\  /  _ \/  _ \ 
|  \/||  \  |  \/||  __\| / \||  \/|| / \| / \ | / \||  \/|  | | \|| / \|
|  __/|  /_ |    /| |   | \_/||    /| |-|| | | | \_/||    /  | |_/|| \_/|
\_/   \____\\_/\_\\_/   \____/\_/\_\\_/ \| \_/ \____/\_/\_\  \____/\____/

⚡ Perforator-Go v2.0 - High-Performance Penetration Testing Framework
🚀 Built for Speed, Scale & Concurrency | By KL3FT3Z
`

var rootCmd = &cobra.Command{
	Use:   "perforator-go",
	Short: "High-performance penetration testing framework",
	Long: color.CyanString(banner) + `
Perforator-Go is a blazing-fast, concurrent penetration testing framework
designed for enterprise-scale security assessments.

Features:
• Concurrent S3 bucket enumeration with goroutines
• Memory-efficient dump analysis with streaming
• API key validation with connection pooling  
• Multi-target scanning with worker pools
• Real-time progress indicators and reporting
• JSON/XML/CSV output formats`,
	PersistentPreRun: func(cmd *cobra.Command, args []string) {
		if !verbose {
			fmt.Print(color.CyanString(banner))
		}
	},
}

func Execute() error {
	return rootCmd.Execute()
}

func init() {
	cobra.OnInitialize(initConfig)

	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is $HOME/.perforator-go.yaml)")
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "verbose output")
	rootCmd.PersistentFlags().IntVarP(&workers, "workers", "w", 50, "number of concurrent workers")
	rootCmd.PersistentFlags().IntVarP(&timeout, "timeout", "t", 10, "request timeout in seconds")
	rootCmd.PersistentFlags().StringVarP(&output, "output", "o", "console", "output format (console, json, xml, csv)")

	viper.BindPFlag("workers", rootCmd.PersistentFlags().Lookup("workers"))
	viper.BindPFlag("timeout", rootCmd.PersistentFlags().Lookup("timeout"))
	viper.BindPFlag("output", rootCmd.PersistentFlags().Lookup("output"))
}

func initConfig() {
	if cfgFile != "" {
		viper.SetConfigFile(cfgFile)
	} else {
		home, err := os.UserHomeDir()
		cobra.CheckErr(err)

		viper.AddConfigPath(home)
		viper.SetConfigType("yaml")
		viper.SetConfigName(".perforator-go")
	}

	viper.AutomaticEnv()

	if err := viper.ReadInConfig(); err == nil && verbose {
		fmt.Fprintln(os.Stderr, "Using config file:", viper.ConfigFileUsed())
	}
}
