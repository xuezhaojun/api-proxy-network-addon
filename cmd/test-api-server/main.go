package main

import (
	"fmt"
	"net/http"
)

func main() {
	err := http.ListenAndServe("127.0.0.1:8000", handler{
		agentID: "agent1",
	})
	if err != nil {
		fmt.Println(err)
	}
}

type handler struct {
	agentID string
}

func (h handler) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	fmt.Println("get request from agent")
	fmt.Println(request.RequestURI)
	_, err := fmt.Fprintf(writer, "hello, I'm %s", h.agentID)
	if err != nil {
		fmt.Println(err)
	}
}
