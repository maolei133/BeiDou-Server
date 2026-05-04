var status;
var savedInput = ""; // 用于保存输入内容

//Start
function start()
{
	status = -1;
	action(1, 0, 0);
}

function action(mode, type, selection)
{
	if (CheckStatus(mode))
	{
		if (status == 0)
		{
			// 第一层：文本输入框
			cm.sendGetText("请输入道具ID和数量（格式：ID [数量]）\r\n例如：2040000 5\r\n不输入数量时默认为1个");
		}
		else if (status == 1 )
		{
			// 保存用户输入
			savedInput = cm.getText();

			// 解析输入
			var parts = savedInput.split(" ");
			var itemId = 0;
			var amount = 1; // 默认数量为1

			// 处理不同输入情况
			if (parts.length == 1) {
				// 只有道具ID
				itemId = parseInt(parts[0]);
			} else if (parts.length >= 2) {
				// 道具ID + 数量
				itemId = parseInt(parts[0]);
				amount = parseInt(parts[1]);
			}

			// 验证数字有效性
			if (isNaN(itemId) || itemId <= 0) {
				cm.sendOk("无效的道具ID！请输入有效的数字");
				cm.dispose();
				return;
			}

			// 验证数量范围 (1-30000)
			if (isNaN(amount) || amount < 1) {
				amount = 1; // 无效数量时重置为1
			} else if (amount > 30000) {
				amount = 30000; // 超过最大值时设为 30000
			}

			// 发放道具
			cm.gainItem(itemId, amount);
			var text = "成功获得 #i" + itemId + "# #b" + amount + "个#k！";
			cm.sendOk(text);
			cm.dispose();
		}
		else
		{
			cm.dispose();
		}
	}
}

// 状态检查函数
function CheckStatus(mode)
{
	if (mode == -1)
	{
		cm.dispose();
		return false;
	}

	if (mode == 1)
	{
		status++;
	}
	else
	{
		status--;
	}

	if (status == -1)
	{
		cm.dispose();
		return false;
	}
	return true;
}