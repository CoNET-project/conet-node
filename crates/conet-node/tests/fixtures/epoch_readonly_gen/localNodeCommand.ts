// EXCERPT, not the full file. Lines 1354-1358 of the TypeScript source, copied verbatim (tabs kept).
// Source: CoNET-SI commit 215afb185dcf0884cbf7f187833308e09ce284fd, path src/util/localNodeCommand.ts.
// Pointer only: git blob of the full file is 0f2b038e8584ab2c9d56e544ebea7401301215c5 (not stored here).
// The generator checks the SHA256 of the lines after the marker line below:
//   d674732159bca51f4e894d9f6185d5ac3bb96c0d4f037c0f6ef6467276d7b821
// ---- excerpt begins ----
	const message = {epoch: validatorData.epoch.toString(), wallet}
	const nodeWallet = ethers.verifyMessage(JSON.stringify(message), validatorData.hash).toLowerCase()
	//logger(`validatorMining [${wallet}]  ********************`)
	if (nodeWallet !== validatorData.nodeWallet.toLowerCase()) {
		logger(Colors.red(`validatorMining verifyMessage hash Error! nodeWallet ${nodeWallet} !== validatorData.nodeWallet.toLowerCase() ${validatorData.nodeWallet.toLowerCase()} wallet = ${wallet}`))
