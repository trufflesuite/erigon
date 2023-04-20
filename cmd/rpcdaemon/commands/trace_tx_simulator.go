package commands

import (
	"context"
	"fmt"
	"math/big"

	"github.com/holiman/uint256"
	libcommon "github.com/ledgerwatch/erigon-lib/common"
	"github.com/ledgerwatch/erigon/common"
	"github.com/ledgerwatch/erigon/common/hexutil"
	"github.com/ledgerwatch/erigon/common/math"
	"github.com/ledgerwatch/erigon/core"
	"github.com/ledgerwatch/erigon/core/state"
	"github.com/ledgerwatch/erigon/core/vm"
	"github.com/ledgerwatch/erigon/rpc"
	"github.com/ledgerwatch/erigon/turbo/rpchelper"
	"github.com/ledgerwatch/erigon/turbo/transactions"
)

type TxCall struct {
	Address  *libcommon.Address `json:"address"`
	Calldata hexutil.Bytes      `json:"calldata"`
}

type TxLog struct {
	Topic           hexutil.Bytes      `json:"topic"`
	Args            hexutil.Bytes      `json:"args"`
	ContractAddress *libcommon.Address `json:"contractAddress"`
}

type SimulationResult struct {
	TotalEthTransfer *big.Int      `json:"total_eth"`
	Output           hexutil.Bytes `json:"output"`
	ErrCode          string        `json:"errcode"`
	Valid            bool          `json:"valid"`
	Calls            []TxCall      `json:"calls"`
	Logs             []TxLog       `json:"logs"`
}

type SimulationTracer struct {
	Resp *SimulationResult
}

func NewSimulationTracer() *SimulationTracer {
	res := &SimulationTracer{}
	res.Resp = &SimulationResult{}
	res.Resp.Calls = make([]TxCall, 0, 1)
	res.Resp.Logs = make([]TxLog, 0, 1)
	res.Resp.TotalEthTransfer = big.NewInt(0)
	res.Resp.Valid = true
	return res
}

// Transaction level
func (st *SimulationTracer) CaptureTxStart(gasLimit uint64) {

}

func (st *SimulationTracer) CaptureTxEnd(restGas uint64) {

}

// Top call frame
func (st *SimulationTracer) CaptureStart(env vm.VMInterface, from libcommon.Address, to libcommon.Address, precompile bool, create bool, input []byte, gas uint64, value *uint256.Int, code []byte) {

}

func (st *SimulationTracer) CaptureEnd(output []byte, usedGas uint64, err error) {

}

// Rest of the frames
func (st *SimulationTracer) CaptureEnter(typ vm.OpCode, from libcommon.Address, to libcommon.Address, precompile bool, create bool, input []byte, gas uint64, value *uint256.Int, code []byte) {

}

func (st *SimulationTracer) CaptureExit(output []byte, usedGas uint64, err error) {

}

// Opcode level
func (st *SimulationTracer) CaptureState(pc uint64, op vm.OpCode, gas, cost uint64, scope *vm.ScopeContext, rData []byte, depth int, err error) {
	if err != nil {
		st.Resp.Valid = false
		st.Resp.ErrCode = err.Error()
		return
	}
	switch op {
	case 0xa1:
		{
			/*
				var stack = [];

					for(var i = 0; i < log.stack.length(); i++) {
						stack.push('0x' + log.stack.peek(i).toString(16));
					}
					var offset = parseInt(stack[0], 16);
					var len = parseInt(stack[1], 16);
					var cd = log.memory.slice(offset, offset + len);
					var str = '0x';
					for(var elem in cd) {
						str += ('0' + (cd[elem] & 0xFF).toString(16)).slice(-2);
					}
					cd = log.contract.getAddress();
					var addr = '0x';
					for(var elem in cd) {
						addr += ('0' + (cd[elem] & 0xFF).toString(16)).slice(-2);
					}
					this.retVal.logs.push({topic: stack[2], args: str, contractAddress: addr});
			*/
			//stackArr := scope.Stack.Data()
			offset := scope.Stack.Back(0).Uint64()
			memlen := scope.Stack.Back(1).Uint64()
			mem := scope.Memory.Data()
			last := offset + memlen
			if last >= uint64(len(mem)) {
				last = uint64(len(mem))
			}
			if offset >= uint64(len(mem)) {
				offset = 0
			}
			args := mem[offset:last]
			topic := scope.Stack.Back(2)
			address := scope.Contract.CodeAddr
			log := TxLog{
				Topic:           topic.Bytes(),
				Args:            args,
				ContractAddress: address,
			}
			st.Resp.Logs = append(st.Resp.Logs, log)
		}
	case 0xf1:
		{
			/*
				f(log.op.toNumber() == 0xf1){
				var stack = [];

				for(var i = 0; i < log.stack.length(); i++) {
					stack.push('0x' + log.stack.peek(i).toString(16));
				}

				var offset = parseInt(stack[3], 16);
				var len = parseInt(stack[4], 16);
				if (len >= 4)
					len = 4;
				var cd = log.memory.slice(offset, offset+len);
				var str = '0x';
				for(var elem in cd) {
					str += ('0' + (cd[elem] & 0xFF).toString(16)).slice(-2);
				}
				this.retVal.calls.push({address: stack[1], calldata: str});

			*/
			//stackArr := scope.Stack.Data()
			offset := scope.Stack.Back(3).Uint64() //stackArr[3].Uint64()
			len := scope.Stack.Back(4).Uint64()
			//fmt.Printf("CaptureState: opcode: %d offset: %s len: %s\n", op, stackArr[3].ToBig().Text(16), stackArr[4].ToBig().Text(16))
			//scope.Stack.Print()
			if len >= 4 {
				len = 4
			}
			mem := scope.Memory.Data()
			if offset+len > uint64(scope.Memory.Len()) {
				return
			}
			calldata := mem[offset : offset+len]
			addr := libcommon.BytesToAddress(scope.Stack.Back(1).Bytes())
			call := TxCall{
				Address:  &addr,
				Calldata: calldata,
			}
			st.Resp.Calls = append(st.Resp.Calls, call)
		}
	default:
		{
			// do nothing
		}
	}
}

func (st *SimulationTracer) CaptureFault(pc uint64, op vm.OpCode, gas, cost uint64, scope *vm.ScopeContext, depth int, err error) {

}

func (api *ErigonImpl) SimulateTransactions(ctx context.Context, args TraceCallParam, traceTypes []string, blockNrOrHash *rpc.BlockNumberOrHash) (*SimulationResult, error) {
	tx, err := api.db.BeginRo(ctx)
	if err != nil {
		return nil, err
	}

	defer tx.Rollback()

	chainConfig, err := api.chainConfig(tx)
	if err != nil {
		return nil, err
	}
	engine := api.engine()

	if blockNrOrHash == nil {
		var num = rpc.LatestBlockNumber
		blockNrOrHash = &rpc.BlockNumberOrHash{BlockNumber: &num}
	}

	blockNumber, hash, _, err := rpchelper.GetBlockNumber(*blockNrOrHash, tx, api.filters)
	if err != nil {
		return nil, err
	}

	stateReader, err := rpchelper.CreateStateReader(ctx, tx, *blockNrOrHash, 0, api.filters, api.stateCache, api.historyV3(tx), chainConfig.ChainName)
	if err != nil {
		return nil, err
	}

	ibs := state.New(stateReader)

	block, err := api.blockWithSenders(tx, hash, blockNumber)
	if err != nil {
		return nil, err
	}
	if block == nil {
		return nil, fmt.Errorf("block %d(%x) not found", blockNumber, hash)
	}
	header := block.Header()

	// Setup context so it may be cancelled the call has completed
	// or, in case of unmetered gas, setup a context with a timeout.
	var cancel context.CancelFunc
	if api.evmCallTimeout > 0 {
		ctx, cancel = context.WithTimeout(ctx, api.evmCallTimeout)
	} else {
		ctx, cancel = context.WithCancel(ctx)
	}

	// Make sure the context is cancelled when the call has completed
	// this makes sure resources are cleaned up.
	defer cancel()

	/* ignore tracetype
	traceResult := &TraceCallResult{Trace: []*ParityTrace{}}
	var traceTypeTrace, traceTypeStateDiff, traceTypeVmTrace bool
	for _, traceType := range traceTypes {
		switch traceType {
		case TraceTypeTrace:
			traceTypeTrace = true
		case TraceTypeStateDiff:
			traceTypeStateDiff = true
		case TraceTypeVmTrace:
			traceTypeVmTrace = true
		default:
			return nil, fmt.Errorf("unrecognized trace type: %s", traceType)
		}
	}
	if traceTypeVmTrace {
		traceResult.VmTrace = &VmTrace{Ops: []*VmTraceOp{}}
	}
	var ot OeTracer
	ot.compat = api.compatibility
	if traceTypeTrace || traceTypeVmTrace {
		ot.r = traceResult
		ot.traceAddr = []int{}
	}*/

	// Get a new instance of the EVM.
	var baseFee *uint256.Int
	if header != nil && header.BaseFee != nil {
		var overflow bool
		baseFee, overflow = uint256.FromBig(header.BaseFee)
		if overflow {
			return nil, fmt.Errorf("header.BaseFee uint256 overflow")
		}
	}
	msg, err := args.ToMessage(500000, baseFee)
	if err != nil {
		return nil, err
	}

	blockCtx := transactions.NewEVMBlockContext(engine, header, blockNrOrHash.RequireCanonical, tx, api._blockReader)
	txCtx := core.NewEVMTxContext(msg)

	blockCtx.GasLimit = math.MaxUint64
	blockCtx.MaxGasLimit = true

	// get an assettracer
	simTracer := NewSimulationTracer()
	evm := vm.NewEVM(blockCtx, txCtx, ibs, chainConfig, vm.Config{Debug: true, Tracer: simTracer})

	// Wait for the context to be done and cancel the evm. Even if the
	// EVM has finished, cancelling may be done (repeatedly)
	go func() {
		<-ctx.Done()
		evm.Cancel()
	}()

	gp := new(core.GasPool).AddGas(msg.Gas())
	var execResult *core.ExecutionResult
	ibs.Prepare(libcommon.Hash{}, libcommon.Hash{}, 0)
	execResult, err = core.ApplyMessage(evm, msg, gp, true /* refunds */, true /* gasBailout */)
	if err != nil {
		return nil, err
	}
	simTracer.Resp.Output = common.CopyBytes(execResult.ReturnData)
	//traceResult.Output = common.CopyBytes(execResult.ReturnData)
	/*if traceTypeStateDiff {
		sdMap := make(map[common.Address]*StateDiffAccount)
		traceResult.StateDiff = sdMap
		sd := &StateDiff{sdMap: sdMap}
		if err = ibs.FinalizeTx(evm.ChainRules(), sd); err != nil {
			return nil, err
		}
		// Create initial IntraBlockState, we will compare it with ibs (IntraBlockState after the transaction)
		initialIbs := state.New(stateReader)
		sd.CompareStates(initialIbs, ibs)
	}*/

	// If the timer caused an abort, return an appropriate error message
	if evm.Cancelled() {
		return nil, fmt.Errorf("execution aborted (timeout = %v)", api.evmCallTimeout)
	}

	return simTracer.Resp, nil
}
