package commands

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"

	"github.com/holiman/uint256"
	libcommon "github.com/ledgerwatch/erigon-lib/common"
	"github.com/ledgerwatch/erigon-lib/kv"
	types2 "github.com/ledgerwatch/erigon-lib/types"
	"github.com/ledgerwatch/erigon/common"
	"github.com/ledgerwatch/erigon/common/hexutil"
	"github.com/ledgerwatch/erigon/common/math"
	"github.com/ledgerwatch/erigon/core"
	"github.com/ledgerwatch/erigon/core/state"
	"github.com/ledgerwatch/erigon/core/types"
	"github.com/ledgerwatch/erigon/core/vm"
	"github.com/ledgerwatch/erigon/rpc"
	"github.com/ledgerwatch/erigon/turbo/adapter/ethapi"
	"github.com/ledgerwatch/erigon/turbo/rpchelper"
	"github.com/ledgerwatch/erigon/turbo/shards"
	"github.com/ledgerwatch/erigon/turbo/transactions"
)

type SimulateTransaction struct {
	Overrides            *ethapi.StateOverrides `json:"overrides"`
	From                 *libcommon.Address     `json:"from"`
	To                   *libcommon.Address     `json:"to"`
	Gas                  *hexutil.Uint64        `json:"gas"`
	GasPrice             *hexutil.Big           `json:"gasPrice"`
	MaxPriorityFeePerGas *hexutil.Big           `json:"maxPriorityFeePerGas"`
	MaxFeePerGas         *hexutil.Big           `json:"maxFeePerGas"`
	Value                *hexutil.Big           `json:"value"`
	Data                 hexutil.Bytes          `json:"data"`
	AccessList           *types2.AccessList     `json:"accessList"`
	txHash               *libcommon.Hash
}

// SimulateParam
type SimulateParam struct {
	Overrides    *ethapi.StateOverrides `json:"overrides"`
	Transactions json.RawMessage        `json:"transactions"` // array of TraceCallParam
	BlockNumber  *rpc.BlockNumberOrHash `json:"block"`
}

type TxCall struct {
	From     *libcommon.Address `json:"from"`
	To       *libcommon.Address `json:"to"`
	Calldata hexutil.Bytes      `json:"calldata"`
	Type     hexutil.Uint       `json:"type"`
	Value    *hexutil.Big       `json:"value,omitempty"`
}

type TxLog struct {
	Topics          []hexutil.Bytes    `json:"topic,omitempty"`
	Args            hexutil.Bytes      `json:"args"`
	ContractAddress *libcommon.Address `json:"contractAddress"`
}

type SimulationResult struct {
	TotalEthTransfer *hexutil.Big  `json:"eth_to_caller"`
	Output           hexutil.Bytes `json:"output"`
	ErrCode          string        `json:"errcode"`
	Valid            bool          `json:"valid"`
	Calls            []*TxCall     `json:"calls,omitempty"`
	Logs             []*TxLog      `json:"logs,omitempty"`
}

type SimulationTracer struct {
	Resp   *SimulationResult
	Caller libcommon.Address
}

func NewSimulationTracer() *SimulationTracer {
	return &SimulationTracer{
		Resp: &SimulationResult{
			Calls:            []*TxCall{},
			Logs:             []*TxLog{},
			TotalEthTransfer: new(hexutil.Big),
			Valid:            true,
		},
	}
}

// Transaction level
func (st *SimulationTracer) CaptureTxStart(gasLimit uint64) {

}

func (st *SimulationTracer) CaptureTxEnd(restGas uint64) {

}

// Top call frame
func (st *SimulationTracer) CaptureStart(env vm.VMInterface, from libcommon.Address, to libcommon.Address, precompile bool, create bool, input []byte, gas uint64, value *uint256.Int, code []byte) {
	if st.Resp.Calls == nil {
		st.Resp.Calls = []*TxCall{}
	}
	if st.Resp.Logs == nil {
		st.Resp.Logs = []*TxLog{}
	}

	st.Resp.Valid = true
	st.Resp.TotalEthTransfer = new(hexutil.Big)
	st.Caller = from
}

func (st *SimulationTracer) CaptureEnd(output []byte, usedGas uint64, err error) {

}

// Rest of the frames
func (st *SimulationTracer) CaptureEnter(typ vm.OpCode, from libcommon.Address, to libcommon.Address, precompile bool, create bool, input []byte, gas uint64, value *uint256.Int, code []byte) {
	call := TxCall{
		From:     &from,
		To:       &to,
		Calldata: input,
		Type:     hexutil.Uint(typ),
	}
	if value != nil {
		call.Value = (*hexutil.Big)(value.ToBig())
	}
	st.Resp.Calls = append(st.Resp.Calls, &call)
	if bytes.Equal(to[:], st.Caller[:]) {
		i := st.Resp.TotalEthTransfer
		i.ToInt().Add(i.ToInt(), value.ToBig())
	}
}

func (st *SimulationTracer) CaptureExit(output []byte, usedGas uint64, err error) {

}

func (st *SimulationTracer) recordLog(scope *vm.ScopeContext, topics int) {
	log := &TxLog{}
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
	address := scope.Contract.CodeAddr
	log.Args = args
	log.ContractAddress = address
	if topics > 0 {
		log.Topics = []hexutil.Bytes{}
	}
	for i := 1; i <= topics; i++ {
		topic := scope.Stack.Back(i + 1)
		log.Topics = append(log.Topics, topic.Bytes())
	}
	st.Resp.Logs = append(st.Resp.Logs, log)
}

// Opcode level
func (st *SimulationTracer) CaptureState(pc uint64, op vm.OpCode, gas, cost uint64, scope *vm.ScopeContext, rData []byte, depth int, err error) {
	if err != nil {
		st.Resp.Valid = false
		st.Resp.ErrCode = err.Error()
		return
	}
	switch op {
	case vm.LOG0:
		{
			st.recordLog(scope, 0)
		}
	case vm.LOG1:
		{
			st.recordLog(scope, 1)
		}
	case vm.LOG2:
		{
			st.recordLog(scope, 2)
		}
	case vm.LOG3:
		{
			st.recordLog(scope, 3)
		}
	case vm.LOG4:
		{
			st.recordLog(scope, 4)
		}
	/*case vm.CALL:
	{

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
	}*/
	default:
		{
			// do nothing
		}
	}
}

func (st *SimulationTracer) CaptureFault(pc uint64, op vm.OpCode, gas, cost uint64, scope *vm.ScopeContext, depth int, err error) {
	st.Resp.Valid = false
	if err != nil {
		st.Resp.ErrCode = err.Error()
	}
}

func (api *ErigonImpl) doSimulateTransactions(ctx context.Context, dbtx kv.Tx, msgs []types.Message, callParams []TraceCallParam, parentNrOrHash *rpc.BlockNumberOrHash, header *types.Header, gasBailout bool, overrides *ethapi.StateOverrides) ([]*SimulationResult, error) {
	chainConfig, err := api.chainConfig(dbtx)
	if err != nil {
		return nil, err
	}
	engine := api.engine()

	if parentNrOrHash == nil {
		var num = rpc.LatestBlockNumber
		parentNrOrHash = &rpc.BlockNumberOrHash{BlockNumber: &num}
	}
	blockNumber, hash, _, err := rpchelper.GetBlockNumber(*parentNrOrHash, dbtx, api.filters)
	if err != nil {
		return nil, err
	}
	stateReader, err := rpchelper.CreateStateReader(ctx, dbtx, *parentNrOrHash, 0, api.filters, api.stateCache, api.historyV3(dbtx), chainConfig.ChainName)
	if err != nil {
		return nil, err
	}
	stateCache := shards.NewStateCache(32, 0 /* no limit */) // this cache living only during current RPC call, but required to store state writes
	cachedReader := state.NewCachedReader(stateReader, stateCache)
	noop := state.NewNoopWriter()
	cachedWriter := state.NewCachedWriter(noop, stateCache)
	ibs := state.New(cachedReader)

	// Override the fields of specified contracts before execution.
	if overrides != nil {
		if err := overrides.Override(ibs); err != nil {
			return nil, err
		}
	}

	// TODO: can read here only parent header
	parentBlock, err := api.blockWithSenders(dbtx, hash, blockNumber)
	if err != nil {
		return nil, err
	}
	parentHeader := parentBlock.Header()
	if parentHeader == nil {
		return nil, fmt.Errorf("parent header %d(%x) not found", blockNumber, hash)
	}

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
	results := []*SimulationResult{}

	useParent := false
	if header == nil {
		header = parentHeader
		useParent = true
	}

	for txIndex, msg := range msgs {
		if err := libcommon.Stopped(ctx.Done()); err != nil {
			return nil, err
		}
		args := callParams[txIndex]
		traceResult := &SimulationResult{}
		/*var traceTypeTrace, traceTypeStateDiff, traceTypeVmTrace bool
		args := callParams[txIndex]
		for _, traceType := range args.traceTypes {
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
		}*/
		/*vmConfig := vm.Config{}
		if (traceTypeTrace && (txIndexNeeded == -1 || txIndex == txIndexNeeded)) || traceTypeVmTrace {
			var ot OeTracer
			ot.compat = api.compatibility
			ot.r = traceResult
			ot.idx = []string{fmt.Sprintf("%d-", txIndex)}
			if traceTypeTrace && (txIndexNeeded == -1 || txIndex == txIndexNeeded) {
				ot.traceAddr = []int{}
			}
			if traceTypeVmTrace {
				traceResult.VmTrace = &VmTrace{Ops: []*VmTraceOp{}}
			}
			vmConfig.Debug = true
			vmConfig.Tracer = &ot
		}*/

		// Get a new instance of the EVM.
		blockCtx := transactions.NewEVMBlockContext(engine, header, parentNrOrHash.RequireCanonical, dbtx, api._blockReader)
		txCtx := core.NewEVMTxContext(msg)

		if useParent {
			blockCtx.GasLimit = math.MaxUint64
			blockCtx.MaxGasLimit = true
		}
		ibs.Reset()
		// Create initial IntraBlockState, we will compare it with ibs (IntraBlockState after the transaction)
		simTracer := NewSimulationTracer()
		simTracer.Resp = traceResult

		evm := vm.NewEVM(blockCtx, txCtx, ibs, chainConfig, vm.Config{Tracer: simTracer, Debug: true})

		gp := new(core.GasPool).AddGas(msg.Gas())
		var execResult *core.ExecutionResult
		// Clone the state cache before applying the changes, clone is discarded
		//var cloneReader state.StateReader
		/*
			if traceTypeStateDiff {
				cloneCache := stateCache.Clone()
				cloneReader = state.NewCachedReader(stateReader, cloneCache)
			}
		*/
		if args.txHash != nil {
			ibs.Prepare(*args.txHash, header.Hash(), txIndex)
		} else {
			ibs.Prepare(libcommon.Hash{}, header.Hash(), txIndex)
		}
		execResult, err = core.ApplyMessage(evm, msg, gp, true /* refunds */, gasBailout /* gasBailout */)
		if err != nil {
			return nil, fmt.Errorf("first run for txIndex %d error: %w", txIndex, err)
		}
		traceResult.Output = common.CopyBytes(execResult.ReturnData)
		/*if traceTypeStateDiff {
			initialIbs := state.New(cloneReader)
			sdMap := make(map[libcommon.Address]*StateDiffAccount)
			traceResult.StateDiff = sdMap
			sd := &StateDiff{sdMap: sdMap}
			if err = ibs.FinalizeTx(evm.ChainRules(), sd); err != nil {
				return nil, err
			}
			sd.CompareStates(initialIbs, ibs)
			if err = ibs.CommitBlock(evm.ChainRules(), cachedWriter); err != nil {
				return nil, err
			}
		} else {*/
		if err = ibs.FinalizeTx(evm.ChainRules(), noop); err != nil {
			return nil, err
		}
		if err = ibs.CommitBlock(evm.ChainRules(), cachedWriter); err != nil {
			return nil, err
		}
		//}
		/*if !traceTypeTrace {
			traceResult.Trace = []*ParityTrace{}
		}*/
		results = append(results, traceResult)
	}
	return results, nil

}

func (api *ErigonImpl) SimulateTransactions(ctx context.Context, parms SimulateParam) ([]*SimulationResult, error) {
	dbtx, err := api.db.BeginRo(ctx)
	if err != nil {
		return nil, err
	}
	defer dbtx.Rollback()

	calls := parms.Transactions
	var callParams []TraceCallParam
	dec := json.NewDecoder(bytes.NewReader(calls))
	tok, err := dec.Token()
	if err != nil {
		return nil, err
	}
	if tok != json.Delim('[') {
		return nil, fmt.Errorf("expected array of [callparam, tracetypes]")
	}
	for dec.More() {
		tok, err = dec.Token()
		if err != nil {
			return nil, err
		}
		if tok != json.Delim('[') {
			return nil, fmt.Errorf("expected [callparam, tracetypes]")
		}
		callParams = append(callParams, TraceCallParam{})
		args := &callParams[len(callParams)-1]
		if err = dec.Decode(args); err != nil {
			return nil, err
		}
		if err = dec.Decode(&args.traceTypes); err != nil {
			return nil, err
		}
		tok, err = dec.Token()
		if err != nil {
			return nil, err
		}
		if tok != json.Delim(']') {
			return nil, fmt.Errorf("expected end of [callparam, tracetypes]")
		}
	}
	tok, err = dec.Token()
	if err != nil {
		return nil, err
	}
	if tok != json.Delim(']') {
		return nil, fmt.Errorf("expected end of array of [callparam, tracetypes]")
	}
	parentNrOrHash := parms.BlockNumber
	var baseFee *uint256.Int
	if parentNrOrHash == nil {
		var num = rpc.LatestBlockNumber
		parentNrOrHash = &rpc.BlockNumberOrHash{BlockNumber: &num}
	}
	blockNumber, hash, _, err := rpchelper.GetBlockNumber(*parentNrOrHash, dbtx, api.filters)
	if err != nil {
		return nil, err
	}

	// TODO: can read here only parent header
	parentBlock, err := api.blockWithSenders(dbtx, hash, blockNumber)
	if err != nil {
		return nil, err
	}
	parentHeader := parentBlock.Header()
	if parentHeader == nil {
		return nil, fmt.Errorf("parent header %d(%x) not found", blockNumber, hash)
	}
	if parentHeader != nil && parentHeader.BaseFee != nil {
		var overflow bool
		baseFee, overflow = uint256.FromBig(parentHeader.BaseFee)
		if overflow {
			return nil, fmt.Errorf("header.BaseFee uint256 overflow")
		}
	}
	msgs := make([]types.Message, len(callParams))
	for i, args := range callParams {
		msgs[i], err = args.ToMessage(5000000000, baseFee)
		if err != nil {
			return nil, fmt.Errorf("convert callParam to msg: %w", err)
		}
	}
	return api.doSimulateTransactions(ctx, dbtx, msgs, callParams, parentNrOrHash, nil, true /* gasBailout */, parms.Overrides)
}
