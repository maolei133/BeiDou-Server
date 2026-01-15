<template>
  <a-modal
    v-model:visible="visibleModel"
    :title="$t('itemSelector.title')"
    width="600px"
    @cancel="handleCancel"
    @ok="handleOk"
  >
    <a-row :gutter="16" style="margin-bottom: 16px">
      <a-col :span="8">
        <a-select
          v-model="condition.type"
          :placeholder="$t('informationSearch.placeholder.type')"
          @change="handleTypeChange"
        >
          <a-option value="eqp">{{
            $t('informationSearch.type.eqp')
          }}</a-option>
          <a-option value="consume">{{
            $t('informationSearch.type.consume')
          }}</a-option>
          <a-option value="ins">{{
            $t('informationSearch.type.ins')
          }}</a-option>
          <a-option value="etc">{{
            $t('informationSearch.type.etc')
          }}</a-option>
          <a-option value="cash">{{
            $t('informationSearch.type.cash')
          }}</a-option>
        </a-select>
      </a-col>
      <a-col v-if="showEquipCategory" :span="8">
        <a-select
          v-model="condition.category"
          :placeholder="$t('informationSearch.placeholder.category')"
          allow-clear
          allow-search
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
        </a-select>
      </a-col>
      <a-col v-if="showEquipSubCategory" :span="8">
        <a-select
          v-model="condition.subCategory"
          :placeholder="$t('informationSearch.placeholder.subCategory')"
          allow-clear
          allow-search
        >
          <a-option
            v-for="option in subCategoryOptions"
            :key="option.value"
            :value="option.value"
          >
            {{ option.label }}
          </a-option>
        </a-select>
      </a-col>
      <a-col :span="8">
        <a-input-search
          v-model="condition.filter"
          :placeholder="$t('informationSearch.placeholder.filter')"
          @search="searchData"
          @press-enter="searchData"
        />
      </a-col>
    </a-row>

    <a-table
      row-key="id"
      :loading="loading"
      :data="informationList"
      :pagination="pagination"
      @page-change="onPageChange"
      @page-size-change="onPageSizeChange"
      @row-click="handleRowClick"
    >
      <template #columns>
        <a-table-column title="ID" data-index="id" :width="100" />
        <a-table-column title="图标" :width="60" align="center">
          <template #cell="{ record }">
            <img :src="getImg(record.type, record.id)" width="32" height="32" />
          </template>
        </a-table-column>
        <a-table-column title="名称" data-index="name" />
      </template>
    </a-table>

    <GiveItemModal
      v-model:visible="equipEditorVisible"
      :title="$t('duey.send.equipStats')"
      :initial-data="equipFormData"
      :is-edit-mode="true"
      @submit="handleEquipEditorSubmit"
    />
  </a-modal>
</template>

<script lang="ts" setup>
  import { ref, reactive, computed, watch } from 'vue';
  import useLoading from '@/hooks/loading';
  import useEquipCategories from '@/hooks/useEquipCategories';
  import { getIconUrl } from '@/utils/mapleStoryAPI';
  import {
    InformationSearch,
    InformationResult,
    informationSearch,
  } from '@/api/information';
  import { getEquInitialInfo, GiveForm } from '@/api/player';
  import GiveItemModal from '@/views/account/player/components/GiveItemModal.vue';

  const props = defineProps<{
    visible: boolean;
  }>();

  const emit = defineEmits(['update:visible', 'select']);

  const { loading, setLoading } = useLoading(false);
  const { categoryOptions, getSubCategoryOptions, loadCategories } =
    useEquipCategories();

  const visibleModel = computed({
    get: () => props.visible,
    set: (val) => emit('update:visible', val),
  });

  const informationList = ref<InformationResult[]>([]);
  const condition = ref<InformationSearch>({
    types: ['eqp'], // 默认选中装备
    filter: '',
    category: undefined,
    subCategory: undefined,
    page: 1,
    pageSize: 10,
  });

  const pagination = reactive({
    current: 1,
    pageSize: 10,
    total: 0,
    showTotal: true,
    showPageSize: true,
    pageSizeOptions: [10, 20, 50],
  });

  const equipEditorVisible = ref(false);
  const equipFormData = ref<GiveForm>({
    type: 6,
    expireType: 0,
  });
  const selectedRecord = ref<InformationResult | null>(null);

  const showEquipCategory = computed(() => {
    return condition.value.types && condition.value.types.includes('eqp');
  });

  // 复用分类逻辑
  const categoryOrder = [
    'Cap',
    'Hair',
    'Face',
    'Accessory',
    'Coat',
    'Longcoat',
    'Pants',
    'Shoes',
    'Glove',
    'Cape',
    'Shield',
    'Weapon',
    'Ring',
    'Android',
    'Mechanic',
    'Dragon',
    'Taming',
    'Bits',
  ];
  const petCategories = ['PetEquip'];

  const sortedCategoryOptions = computed(() => {
    const options = [...categoryOptions.value];
    return options.sort((a, b) => {
      const indexA = categoryOrder.indexOf(a.value);
      const indexB = categoryOrder.indexOf(b.value);
      if (indexA !== -1 && indexB !== -1) return indexA - indexB;
      if (indexA !== -1) return -1;
      if (indexB !== -1) return 1;
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

  const subCategoryOptions = computed(() => {
    if (condition.value.category) {
      return getSubCategoryOptions(condition.value.category);
    }
    return [];
  });

  const showEquipSubCategory = computed(() => {
    return (
      showEquipCategory.value &&
      condition.value.category &&
      subCategoryOptions.value.length > 0
    );
  });

  const getImg = (type: string, id: number) => {
    let imgType = type.toLowerCase();
    if (['cash', 'consume', 'eqp', 'etc', 'ins', 'pet'].includes(type)) {
      imgType = 'item';
    }
    return getIconUrl(imgType, id);
  };

  const fetchData = async () => {
    setLoading(true);
    try {
      const { data } = await informationSearch({
        ...condition.value,
        page: pagination.current,
        pageSize: pagination.pageSize,
      });
      if (data && Array.isArray(data.records)) {
        informationList.value = data.records;
        pagination.total = data.totalRow;
      } else {
        informationList.value = [];
        pagination.total = 0;
      }
    } catch (err) {
      informationList.value = [];
      pagination.total = 0;
    } finally {
      setLoading(false);
    }
  };

  const searchData = () => {
    pagination.current = 1;
    fetchData();
  };

  const handleTypeChange = (val: any) => {
    // val is string here because a-select v-model is string for single select
    // but condition.types is string[]
    condition.value.types = [val];
    if (val === 'eqp') {
      loadCategories();
    } else {
      condition.value.category = undefined;
      condition.value.subCategory = undefined;
    }
    searchData();
  };

  const handleCategoryChange = () => {
    condition.value.subCategory = undefined;
    searchData();
  };

  const onPageChange = (current: number) => {
    pagination.current = current;
    fetchData();
  };

  const onPageSizeChange = (pageSize: number) => {
    pagination.pageSize = pageSize;
    pagination.current = 1;
    fetchData();
  };

  const handleRowClick = async (record: InformationResult) => {
    selectedRecord.value = record;

    if (record.type === 'Eqp') {
      // 如果是装备，弹出编辑框
      try {
        const { data } = await getEquInitialInfo(record.id);
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        const equipData = data as any;

        equipFormData.value = {
          type: 6,
          id: record.id,
          str: equipData.str || 0,
          dex: equipData.dex || 0,
          int: equipData.int || 0,
          luk: equipData.luk || 0,
          hp: equipData.hp || 0,
          mp: equipData.mp || 0,
          pAtk: equipData.pad || 0,
          mAtk: equipData.mad || 0,
          pDef: equipData.pdd || 0,
          mDef: equipData.mdd || 0,
          acc: equipData.acc || 0,
          avoid: equipData.eva || 0,
          hands: equipData.hands || 0,
          speed: equipData.speed || 0,
          jump: equipData.jump || 0,
          upgradeSlot: equipData.tuc || 0,
          expireType: 0,
        };
        equipEditorVisible.value = true;
      } catch (e) {
        // 如果获取失败，直接选中
        emit('select', record);
        visibleModel.value = false;
      }
    } else {
      // 其他物品直接选中
      emit('select', record);
      visibleModel.value = false;
    }
  };

  const handleEquipEditorSubmit = (data: GiveForm) => {
    // 将编辑后的属性合并到 selectedRecord 中返回
    // 注意：InformationResult 没有这些属性，所以接收方需要处理
    const result = {
      ...selectedRecord.value,
      ...data,
      // 映射回 SendDueyModal 需要的字段名
      watk: data.pAtk,
      matk: data.mAtk,
      wdef: data.pDef,
      mdef: data.mDef,
      upgradeSlots: data.upgradeSlot,
    };
    emit('select', result);
    equipEditorVisible.value = false;
    visibleModel.value = false;
  };

  const handleCancel = () => {
    visibleModel.value = false;
  };

  const handleOk = () => {
    // 移除 OK 按钮的逻辑，改为点击行即选中
    // 但为了兼容性，如果用户没点行直接点 OK（虽然现在没选中行），可以关闭
    visibleModel.value = false;
  };

  watch(
    () => props.visible,
    (val) => {
      if (val) {
        loadCategories();
        searchData();
        selectedRecord.value = null;
      }
    }
  );
</script>
