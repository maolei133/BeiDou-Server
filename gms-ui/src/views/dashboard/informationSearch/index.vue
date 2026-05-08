<template>
  <div class="container gms-page">
    <Breadcrumb />
    <a-card
      class="general-card"
      :title="$t('menu.dashboard.informationSearch')"
    >
      <a-row>
        <a-select
          v-model="condition.types"
          :placeholder="$t('informationSearch.placeholder.type')"
          multiple
          :max-tag-count="3"
          allow-clear
          class="a-space-son"
          @change="handleTypeChange"
        >
          <a-option value="cash">
            {{ $t('informationSearch.type.cash') }}
          </a-option>
          <a-option value="consume">
            {{ $t('informationSearch.type.consume') }}
          </a-option>
          <a-option value="eqp">
            {{ $t('informationSearch.type.eqp') }}
          </a-option>
          <a-option value="etc">
            {{ $t('informationSearch.type.etc') }}
          </a-option>
          <a-option value="ins">
            {{ $t('informationSearch.type.ins') }}
          </a-option>
          <a-option value="map">
            {{ $t('informationSearch.type.map') }}
          </a-option>
          <a-option value="mob">
            {{ $t('informationSearch.type.mob') }}
          </a-option>
          <a-option value="npc">
            {{ $t('informationSearch.type.npc') }}
          </a-option>
          <a-option value="pet">
            {{ $t('informationSearch.type.pet') }}
          </a-option>
          <a-option value="skill">
            {{ $t('informationSearch.type.skill') }}
          </a-option>
        </a-select>

        <a-select
          v-if="showEquipCategory"
          v-model="condition.category"
          :placeholder="$t('informationSearch.placeholder.category')"
          allow-clear
          allow-search
          class="a-space-son"
          @change="handleCategoryChange"
        >
          <a-opt-group :label="$t('informationSearch.group.character')">
            <a-option
              v-for="option in characterCategoryOptions"
              :key="option.value"
              :value="option.value"
            >
              {{ option.label }}
            </a-option>
          </a-opt-group>
          <a-opt-group :label="$t('informationSearch.group.pet')">
            <a-option
              v-for="option in petCategoryOptions"
              :key="option.value"
              :value="option.value"
            >
              {{ option.label }}
            </a-option>
          </a-opt-group>
          <a-opt-group :label="$t('informationSearch.group.other')">
            <a-option
              v-for="option in otherCategoryOptions"
              :key="option.value"
              :value="option.value"
            >
              {{ option.label }}
            </a-option>
          </a-opt-group>
        </a-select>

        <a-select
          v-if="showEquipSubCategory"
          v-model="condition.subCategory"
          :placeholder="$t('informationSearch.placeholder.subCategory')"
          allow-clear
          allow-search
          class="a-space-son"
        >
          <a-opt-group
            v-if="characterSubCategoryOptions.length > 0"
            :label="$t('informationSearch.group.character')"
          >
            <a-option
              v-for="option in characterSubCategoryOptions"
              :key="option.value"
              :value="option.value"
            >
              {{ option.label }}
            </a-option>
          </a-opt-group>
          <a-opt-group
            v-if="petSubCategoryOptions.length > 0"
            :label="$t('informationSearch.group.pet')"
          >
            <a-option
              v-for="option in petSubCategoryOptions"
              :key="option.value"
              :value="option.value"
            >
              {{ option.label }}
            </a-option>
          </a-opt-group>
        </a-select>

        <a-input
          v-model="condition.filter"
          :placeholder="$t('informationSearch.placeholder.filter')"
          class="a-space-son"
        />
        <a-button type="primary" @click="searchData">
          {{ $t('button.search') }}
        </a-button>
        <a-button @click="resetSearch">
          {{ $t('button.reset') }}
        </a-button>
      </a-row>
      <a-table
        row-key="id"
        :loading="loading"
        :data="informationList"
        column-resizable
        :pagination="pagination"
        :bordered="{ wrapper: true, cell: true }"
        @page-change="onPageChange"
        @page-size-change="onPageSizeChange"
      >
        <template #columns>
          <a-table-column
            :title="$t('informationSearch.column.type')"
            data-index="type"
            align="center"
          >
            <template #cell="{ record }">
              <a-tag color="arcoblue">
                {{ getTag(record.type) }}
              </a-tag>
            </template>
          </a-table-column>
          <a-table-column
            :title="$t('informationSearch.column.id')"
            data-index="id"
            align="center"
          />
          <a-table-column
            :title="$t('informationSearch.column.name')"
            data-index="name"
            align="center"
          >
            <template #cell="{ record }">
              <a-popover>
                <a-button type="text" size="mini">
                  {{ record.name }}
                </a-button>
                <template #content>
                  <img :src="getImg(record.type, record.id)" alt="" />
                </template>
              </a-popover>
            </template>
          </a-table-column>
          <a-table-column
            :title="$t('informationSearch.column.desc')"
            data-index="desc"
            align="center"
            :width="400"
            :style="{ minWidth: '400px' }"
          />
        </template>
      </a-table>
    </a-card>
  </div>
</template>

<script lang="ts" setup>
  import { ref, reactive, computed } from 'vue';
  import { useI18n } from 'vue-i18n';
  import { Message } from '@arco-design/web-vue';
  import useLoading from '@/hooks/loading';
  import useEquipCategories from '@/hooks/useEquipCategories';
  import { getIconUrl } from '@/utils/mapleStoryAPI';
  import {
    InformationSearch,
    InformationResult,
    informationSearch,
  } from '@/api/information';

  const { t } = useI18n();
  const { loading, setLoading } = useLoading(false);
  const { categoryOptions, getSubCategoryOptions, loadCategories } =
    useEquipCategories();

  const informationList = ref<InformationResult[]>([]);
  const condition = ref<InformationSearch>({
    types: [],
    filter: '',
    category: undefined,
    subCategory: undefined,
    page: 1,
    pageSize: 20,
  });

  const pagination = reactive({
    current: 1,
    pageSize: 20,
    total: 0,
    showTotal: true,
    showPageSize: true,
    pageSizeOptions: [10, 20, 50, 100],
    showJumper: true,
  });

  const showEquipCategory = computed(() => {
    return condition.value.types && condition.value.types.includes('eqp');
  });

  // 定义装备部位的排序顺序 (从头到脚)
  const categoryOrder = [
    'Cap', // 帽子
    'Hair', // 发型 (虽然通常是独立类型，但在装备分类中可能出现)
    'Face', // 脸饰
    'Accessory', // 饰品
    'Coat', // 上衣
    'Longcoat', // 套服
    'Pants', // 裤子
    'Shoes', // 鞋子
    'Glove', // 手套
    'Cape', // 披风
    'Shield', // 盾牌
    'Weapon', // 武器
    'Ring', // 戒指
    'Android', // 安卓
    'Mechanic', // 机械师
    'Dragon', // 龙神
    'Taming', // 骑宠
    'Bits', // 组件
  ];

  // 宠物相关分类
  const petCategories = ['PetEquip'];

  // 对分类选项进行分组和排序
  const sortedCategoryOptions = computed(() => {
    const options = [...categoryOptions.value];
    return options.sort((a, b) => {
      const indexA = categoryOrder.indexOf(a.value);
      const indexB = categoryOrder.indexOf(b.value);
      // 如果都在排序列表中，按列表顺序
      if (indexA !== -1 && indexB !== -1) return indexA - indexB;
      // 如果只有一个在列表中，在列表中的排前面
      if (indexA !== -1) return -1;
      if (indexB !== -1) return 1;
      // 都不在列表中，按字母顺序
      return a.value.localeCompare(b.value);
    });
  });

  const characterCategoryOptions = computed(() => {
    return sortedCategoryOptions.value.filter(
      (opt) => !petCategories.includes(opt.value)
    );
  });

  const petCategoryOptions = computed(() => {
    return sortedCategoryOptions.value.filter((opt) =>
      petCategories.includes(opt.value)
    );
  });

  const otherCategoryOptions = computed(() => {
    // 可以在这里放一些未归类的，目前假设都归类了
    return [];
  });

  const subCategoryOptions = computed(() => {
    if (condition.value.category) {
      return getSubCategoryOptions(condition.value.category);
    }
    return [];
  });

  // 子分类排序顺序 (从头到脚)
  const subCategoryOrder = [
    // 饰品类
    'FACE_ACCESSORY', // 脸饰
    'EYE_ACCESSORY', // 眼饰
    'EARRINGS', // 耳环
    'SHOULDER', // 肩饰
    'PENDANT', // 项链
    'MEDAL', // 勋章
    'BELT', // 腰带
    'RING', // 戒指

    // 武器类 (按攻击距离或类型排序)
    'SWORD', // 单手剑
    'AXE', // 单手斧
    'MACE', // 单手钝器
    'DAGGER', // 短刀
    'WAND', // 短杖
    'STAFF', // 长杖
    'SWORD_2H', // 双手剑
    'AXE_2H', // 双手斧
    'MACE_2H', // 双手钝器
    'SPEAR', // 枪
    'POLEARM', // 矛
    'BOW', // 弓
    'CROSSBOW', // 弩
    'CLAW', // 拳套
    'KNUCKLER', // 指虎
    'PISTOL', // 手铳
  ];

  const sortedSubCategoryOptions = computed(() => {
    const options = [...subCategoryOptions.value];
    return options.sort((a, b) => {
      const indexA = subCategoryOrder.indexOf(a.value);
      const indexB = subCategoryOrder.indexOf(b.value);
      if (indexA !== -1 && indexB !== -1) return indexA - indexB;
      if (indexA !== -1) return -1;
      if (indexB !== -1) return 1;
      return a.value.localeCompare(b.value);
    });
  });

  const characterSubCategoryOptions = computed(() => {
    // 假设所有目前的子分类都是人物装备
    // 如果有宠物装备的子分类，需要在这里过滤
    return sortedSubCategoryOptions.value.filter(
      (opt) => !opt.value.startsWith('PET_')
    );
  });

  const petSubCategoryOptions = computed(() => {
    // 宠物装备子分类
    return sortedSubCategoryOptions.value.filter((opt) =>
      opt.value.startsWith('PET_')
    );
  });

  const showEquipSubCategory = computed(() => {
    return (
      showEquipCategory.value &&
      condition.value.category &&
      subCategoryOptions.value.length > 0
    );
  });

  const handleTypeChange = () => {
    if (showEquipCategory.value) {
      loadCategories();
    } else {
      condition.value.category = undefined;
      condition.value.subCategory = undefined;
    }
  };

  const handleCategoryChange = () => {
    condition.value.subCategory = undefined;
  };

  const getImg = (type: string, id: number) => {
    let imgType = type.toLowerCase();
    if (['cash', 'consume', 'eqp', 'etc', 'ins', 'pet'].includes(type)) {
      imgType = 'item';
    }
    return getIconUrl(imgType, id);
  };

  const fetchData = async (
    params: InformationSearch = {
      types: [],
      filter: '',
      page: 1,
      pageSize: 20,
    }
  ) => {
    setLoading(true);
    try {
      const { data } = await informationSearch(params);
      if (data && Array.isArray(data.records)) {
        informationList.value = data.records;
        pagination.current = params.page || 1;
        pagination.pageSize = params.pageSize || 20;
        pagination.total = data.totalRow;
      } else {
        informationList.value = [];
        pagination.total = 0;
        console.warn('Unexpected API response structure:', data);
      }
    } catch (err) {
      console.error('Search failed:', err);
      informationList.value = [];
      pagination.total = 0;
    } finally {
      setLoading(false);
    }
  };

  const searchData = () => {
    if (
      !condition.value.filter &&
      !condition.value.category &&
      !condition.value.subCategory
    ) {
      Message.error({
        content: t('informationSearch.check.filter'),
        duration: 3 * 1000,
      });
      return;
    }
    condition.value.page = 1;
    fetchData(condition.value);
  };

  const onPageChange = (current: number) => {
    condition.value.page = current;
    fetchData(condition.value);
  };

  const onPageSizeChange = (pageSize: number) => {
    condition.value.pageSize = pageSize;
    condition.value.page = 1; // 切换每页条数时重置到第一页
    fetchData(condition.value);
  };

  const resetSearch = () => {
    condition.value.types = [];
    condition.value.filter = '';
    condition.value.category = undefined;
    condition.value.subCategory = undefined;
    condition.value.page = 1;
    condition.value.pageSize = 20;
    informationList.value = [];
    pagination.total = 0;
    pagination.current = 1;
    pagination.pageSize = 20;
  };

  const getTag = (type: string) => {
    let tag;
    switch (type) {
      case 'cash':
      case 'consume':
      case 'eqp':
      case 'etc':
      case 'ins':
      case 'map':
      case 'mob':
      case 'npc':
      case 'pet':
      case 'skill':
        tag = t(`informationSearch.type.${type}`);
        break;
      default:
        tag = type;
        break;
    }
    return tag;
  };
</script>

<script lang="ts">
  export default {
    name: 'InformationSearch',
  };
</script>

<style lang="less" scoped>
  .arco-card-body > .arco-row > {
    display: flex;
    flex-wrap: wrap;
    gap: 16px;
  }
  :deep(.a-space-son) {
    width: 400px;
    max-width: 100%;
  }
  :deep(.arco-table-th:nth-child(1)) {
    min-width: 70px;
  }
  :deep(.arco-table-th:nth-child(2)) {
    min-width: 100px;
  }
  :deep(.arco-table-th:nth-child(3)) {
    min-width: 50px;
    max-width: 150px;
  }
  :deep(.arco-table-th:nth-child(4)) {
    min-width: 400px;
  }
</style>
