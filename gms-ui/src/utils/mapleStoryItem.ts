/**
 * 解析冒险岛文本中的颜色代码
 * 例如: #c内容# -> <span style="color: #FF9900;">内容</span>
 */
export function parseMapleText(text: string): string {
  if (!text) return '';
  // 替换 #c...# 为橙色
  let parsed = text.replace(
    /#c([^#]*)#/g,
    '<span style="color: #FF9900;">$1</span>'
  );
  // 这里可以扩展其他颜色代码，例如 #b(蓝色), #r(红色), #g(绿色) 等
  // 暂时只处理用户提到的 #c

  // 处理换行符: 将 \n 和 \\n 都替换为 <br>
  parsed = parsed.replace(/\\n/g, '<br>').replace(/\n/g, '<br>');
  return parsed;
}

/**
 * 物品 Flag 定义
 */
export const ItemFlags = {
  LOCK: 0x01,
  SPIKES: 0x02,
  COLD: 0x04,
  UNTRADEABLE: 0x08,
  KARMA: 0x10,
  CHARM_EXP: 0x20,
  PET_COME: 0x80,
  ACCOUNT_SHARING: 0x100,
  MERGE_UNTRADEABLE: 0x200,
};

/**
 * 检查 Flag 是否包含特定位
 */
export function hasFlag(flag: number, target: number): boolean {
  // eslint-disable-next-line no-bitwise
  return (flag & target) === target;
}

/**
 * 根据 ItemId 获取装备分类名称 (简易版)
 */
export function getEquipCategory(itemId: number): string {
  const idStr = itemId.toString();
  const prefix = parseInt(idStr.substring(0, 3), 10);

  if (prefix === 100) return 'Cap';
  if (prefix === 104) return 'Coat';
  if (prefix === 105) return 'Longcoat';
  if (prefix === 106) return 'Pants';
  if (prefix === 107) return 'Shoes';
  if (prefix === 108) return 'Glove';
  if (prefix === 109) return 'Shield';
  if (prefix === 110) return 'Cape';
  if (prefix === 111) return 'Ring';
  if (prefix === 112) return 'Pendant';
  if (prefix === 113) return 'Belt';
  if (prefix === 114) return 'Medal';
  if (prefix === 115) return 'Shoulder';
  if (prefix === 116) return 'Pocket';
  if (prefix === 118) return 'Badge';
  if (prefix === 119) return 'Emblem';
  if (prefix === 161) return 'Mechanic';
  if (prefix === 166) return 'Android';
  if (prefix === 167) return 'Android Heart';
  if (prefix >= 190 && prefix <= 197) return 'Dragon';

  // 武器
  if (prefix >= 121 && prefix <= 129) return 'Weapon'; // 各种法杖魔棒等
  if (prefix === 130) return 'One-Handed Sword';
  if (prefix === 131) return 'One-Handed Axe';
  if (prefix === 132) return 'One-Handed Mace';
  if (prefix === 133) return 'Dagger';
  if (prefix === 134) return 'Katara';
  if (prefix === 136) return 'Cane';
  if (prefix === 137) return 'Wand';
  if (prefix === 138) return 'Staff';
  if (prefix === 140) return 'Two-Handed Sword';
  if (prefix === 141) return 'Two-Handed Axe';
  if (prefix === 142) return 'Two-Handed Mace';
  if (prefix === 143) return 'Spear';
  if (prefix === 144) return 'Polearm';
  if (prefix === 145) return 'Bow';
  if (prefix === 146) return 'Crossbow';
  if (prefix === 147) return 'Claw';
  if (prefix === 148) return 'Knuckle';
  if (prefix === 149) return 'Gun';
  if (prefix === 152) return 'Dual Bowguns';
  if (prefix === 153) return 'Hand Cannon';

  return 'Equip';
}

/**
 * 判断是否为装备
 */
export function isEquip(itemId: number): boolean {
  return Math.floor(itemId / 1000000) === 1;
}
