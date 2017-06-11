package main

import "fmt"

type person struct {
	name string
}

type org struct {
	name  string
	group []person
}

func main() {

	google := org{name: "google"}

	google.group = make([]person, 0, 10)

	jim := person{name: "jim"}

	google.group = append(google.group, jim)

	hans := person{name: "hans"}

	google.group = append(google.group, hans)

	tom := person{name: "tom"}

	google.group = append(google.group, tom)

	fmt.Println("len of google.group", len(google.group))

	foo := make([]string, 10, 10)

	for i, a := range foo {
		if foo[i] == nil {
			fmt.Println("i is empty")
		}
	}

}
