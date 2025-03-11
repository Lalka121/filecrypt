// Package textstyler provides an unified way of
// styling text using fatih/color library.
package textstyler

import (
	"github.com/fatih/color"
)

var (
	baseTextStyle = color.New(color.FgWhite)

	successTextStyle = color.New(color.FgGreen).Add(color.Bold)
	errorTextStyle = color.New(color.FgRed).Add(color.Bold)

	titleTextStyle = color.New(color.FgCyan).Add(color.Bold)
	subtitleTextStyle = color.New(color.FgCyan).Add(color.Italic)
	labelTextStyle = color.New(color.FgWhite)
)

func Sprint(a ...interface{}) string {
	return baseTextStyle.Sprint(a...)
}

func Sprintf(format string, a ...interface{}) string {
	return successTextStyle.Sprintf(format, a...)
}

func Success(a ...interface{}) string {
	return successTextStyle.Sprint(a...)
}

func Successf(format string, a ...interface{}) string {
	return successTextStyle.Sprintf(format, a...)
}

func Error(a ...interface{}) string {
	return errorTextStyle.Sprint(a...)
}

func Errorf(format string, a ...interface{}) string {
	return errorTextStyle.Sprintf(format, a...)
}

func Title(a ...interface{}) string {
	return titleTextStyle.Sprint(a...)
}

func Titlef(format string, a ...interface{}) string {
	return titleTextStyle.Sprintf(format, a...)
}

func Subtitle(a ...interface{}) string {
	return subtitleTextStyle.Sprint(a...)
}

func Subtitlef(format string, a ...interface{}) string {
	return subtitleTextStyle.Sprintf(format, a...)
}

func Label(a ...interface{}) string {
	return labelTextStyle.Sprint(a...)
}

func Labelf(format string, a ...interface{}) string {
	return labelTextStyle.Sprintf(format, a...)
}