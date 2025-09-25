package examples

import "testing"

// 1: cd to current path
// 2: use command like this: go test  -v -test.run Test_Example
func Test_Example(t *testing.T) {
	ExampleWithFixedKeys()
	ExampleWithEphemeralKeys()
	ExampleWithDifferentCurves()
	ExampleWithPEMFiles()
	ExamplePerformanceTest()
}
