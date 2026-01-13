import { ref, computed } from 'vue';
import { useI18n } from 'vue-i18n';
import { getEquipCategories } from '@/api/information';

export default function useEquipCategories() {
  const { t } = useI18n();
  const rawCategories = ref<string[]>([]);
  const loading = ref(false);

  // 计算属性：自动将原始 Key 转换为 { label, value } 格式
  // 并且会随着语言切换自动更新 label
  const categoryOptions = computed(() => {
    return rawCategories.value.map((cat) => {
      const key = `informationSearch.equipCategory.${cat}`;
      const translated = t(key);
      // 如果翻译结果等于 key，说明没找到翻译，此时显示原始分类名
      return {
        value: cat, // 发送给后端的值 (Weapon)
        label: translated !== key ? translated : cat, // 展示给用户的值 (武器 或 Weapon)
      };
    });
  });

  const loadCategories = async () => {
    // 如果已经加载过，就不再重复请求
    if (rawCategories.value.length > 0) return;

    loading.value = true;
    try {
      const { data } = await getEquipCategories();
      rawCategories.value = data;
    } catch (err) {
      console.error('Failed to load equip categories:', err);
    } finally {
      loading.value = false;
    }
  };

  return {
    rawCategories,
    categoryOptions,
    loadCategories,
    loading,
  };
}
