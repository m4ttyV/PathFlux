package main

import (
	"encoding/json"
	"fmt"
	T "github.com/sagernet/sing-box/common/pathfluxtree"
	"github.com/spf13/cobra"
	"strconv"
)

func init() {
	mainCommand.AddCommand(&cobra.Command{Use: "pathflux-process-identity <pid>", Args: cobra.ExactArgs(1), RunE: func(cmd *cobra.Command, args []string) error {
		pid, err := strconv.ParseUint(args[0], 10, 32)
		if err != nil {
			return T.ErrUnavailable
		}
		p, err := (T.NativeSource{}).Read(uint32(pid))
		if err != nil {
			return err
		}
		b, err := json.Marshal(p)
		if err == nil {
			fmt.Println(string(b))
		}
		return err
	}})
	mainCommand.AddCommand(&cobra.Command{Use: "pathflux-capabilities", Args: cobra.NoArgs, Run: func(cmd *cobra.Command, args []string) {
		fmt.Println(`{"protocol":3,"processTree":true,"pidCreationTime":true,"processSequenceNumber":true,"decisionSnapshot":true,"udpOwnerGuard":true,"experimental":true}`)
	}})
}
