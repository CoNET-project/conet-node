// Verbatim from CoNET-SI src/util/htmlResponse.ts distorySocketPayment (rev 74c6cfd): the 402 page body.
export const paymentRequiredHtml = (): string => {
	const contentTitle = `402 Payment Required`
	const contectBody = `CoNET Passport has expired Please purchase a new certificate\r\nCoNETパスポートの有効期限が切れています。新しいを購入してください。\r\nCoNET通证已过期请购买新证书`
	const responseHtml = `<html>\r\n<head><title>${contentTitle}</title></head>\r\n<body>\r\n<center><h1>${contectBody}</h1></center>\r\n<hr><center>nginx/1.18.0</center>\r\n</body>\r\n</html>\r\n`
	return responseHtml
}
