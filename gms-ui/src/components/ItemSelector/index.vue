<template>
  <a-modal
    v-model:visible="visibleModel"
    :title="$t('itemSelector.title')"
    width="800px"
    :body-style="{
      height: '600px',
      display: 'flex',
      flexDirection: 'column',
      overflow: 'hidden',
    }"
    @cancel="handleCancel"
    @ok="handleOk"
  >
    <div class="filter-container">
      <a-select
        v-model="selectedType"
        :placeholder="$t('informationSearch.placeholder.type')"
        allow-clear
        style="width: 120px"
        @change="handleTypeChange"
        @clear="handleTypeClear"
      >
        <a-option value="eqp">{{ $t('informationSearch.type.eqp') }}</a-option>
        <a-option value="consume">{{
          $t('informationSearch.type.consume')
        }}</a-option>
        <a-option value="ins">{{ $t('informationSearch.type.ins') }}</a-option>
        <a-option value="etc">{{ $t('informationSearch.type.etc') }}</a-option>
        <a-option value="cash">{{
          $t('informationSearch.type.cash')
        }}</a-option>
      </a-select>

      <a-select
        v-if="showEquipCategory"
        v-model="condition.category"
        :placeholder="$t('informationSearch.placeholder.category')"
        allow-clear
        allow-search
        style="width: 120px"
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

      <a-select
        v-if="showEquipSubCategory"
        v-model="condition.subCategory"
        :placeholder="$t('informationSearch.placeholder.subCategory')"
        allow-clear
        allow-search
        style="width: 120px"
        @change="handleSubCategoryChange"
      >
        <a-option
          v-for="option in subCategoryOptions"
          :key="option.value"
          :value="option.value"
        >
          {{ option.label }}
        </a-option>
      </a-select>

      <a-input-search
        v-model="condition.filter"
        :placeholder="$t('informationSearch.placeholder.filter')"
        style="flex: 1; min-width: 200px"
        @search="searchData"
        @press-enter="searchData"
      />
    </div>

    <div style="flex: 1; overflow: hidden; position: relative">
      <a-table
        row-key="id"
        :loading="loading"
        :data="informationList"
        :pagination="false"
        :scroll="{ y: '100%' }"
        style="height: 100%"
        @row-click="handleRowClick"
      >
        <template #columns>
          <a-table-column title="ID" data-index="id" :width="100" />
          <a-table-column title="图标" :width="60" align="center">
            <template #cell="{ record }">
              <img
                :src="getImg(record.type, record.id)"
                width="32"
                height="32"
              />
            </template>
          </a-table-column>
          <a-table-column title="名称" data-index="name" />
        </template>
      </a-table>
    </div>

    <div class="pagination-container">
      <a-pagination
        :total="pagination.total"
        :current="pagination.current"
        :page-size="pagination.pageSize"
        show-total
        @change="onPageChange"
      >
        <template #total>
          <!-- Hide default total -->
        </template>
      </a-pagination>

      <div class="pagination-controls">
        <span class="total-text">
          {{ $t('itemSelector.pagination.total', { total: pagination.total }) }}
        </span>
        <div class="controls-right">
          <a-select
            v-model="pagination.pageSize"
            style="width: 120px"
            @change="onPageSizeChange"
          >
            <a-option :value="10">{{
              $t('itemSelector.pagination.page', { count: 10 })
            }}</a-option>
            <a-option :value="20">{{
              $t('itemSelector.pagination.page', { count: 20 })
            }}</a-option>
            <a-option :value="50">{{
              $t('itemSelector.pagination.page', { count: 50 })
            }}</a-option>
          </a-select>
          <span style="margin: 0 8px">{{
            $t('itemSelector.pagination.goto')
          }}</span>
          <a-input-number
            v-model="jumpPage"
            style="width: 60px"
            @press-enter="handleJumpPage"
          />
        </div>
      </div>
    </div>

    <GiveItemModal
      v-if="equipEditorVisible"
      v-model:visible="equipEditorVisible"
      :title="$t('duey.send.equipStats')"
      :initial-data="equipFormData"
      :is-edit-mode="true"
      @submit="handleEquipEditorSubmit"
    />
  </a-modal>
</template>

<script lang="ts" setup>
  import { ref, reactive, computed, watch, defineAsyncComponent } from 'vue';
  import { useI18n } from 'vue-i18n';
  import useLoading from '@/hooks/loading';
  import useEquipCategories from '@/hooks/useEquipCategories';
  import { getIconUrl } from '@/utils/mapleStoryAPI';
  import {
    InformationSearch,
    InformationResult,
    informationSearch,
  } from '@/api/information';
  import { getEquInitialInfo, GiveForm } from '@/api/player';

  // 使用异步组件解决循环引用问题
  const GiveItemModal = defineAsyncComponent(
    () => import('@/views/account/player/components/GiveItemModal.vue')
  );

  const props = defineProps<{
    visible: boolean;
    initialId?: number;
  }>();

  const emit = defineEmits(['update:visible', 'select']);

  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  const { t } = useI18n();
  const { loading, setLoading } = useLoading(false);
  const { categoryOptions, getSubCategoryOptions, loadCategories } =
    useEquipCategories();

  const visibleModel = computed({
    get: () => props.visible,
    set: (val) => emit('update:visible', val),
  });

  const informationList = ref<InformationResult[]>([]);
  const condition = ref<InformationSearch>({
    types: [],
    filter: '',
    category: undefined,
    subCategory: undefined,
    page: 1,
    pageSize: 10,
  });

  const selectedType = ref<string | undefined>(undefined);
  const jumpPage = ref(1);

  const pagination = reactive({
    current: 1,
    pageSize: 10,
    total: 0,
    totalPage: 0,
    showTotal: false,
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
      const searchCondition = {
        ...condition.value,
        page: pagination.current,
        pageSize: pagination.pageSize,
      };

      // 如果没有选择类型，默认搜索所有类型
      if (!searchCondition.types || searchCondition.types.length === 0) {
        searchCondition.types = ['eqp', 'consume', 'ins', 'etc', 'cash'];
      }

      const { data } = await informationSearch(searchCondition);
      if (data && Array.isArray(data.records)) {
        informationList.value = data.records;
        pagination.total = data.totalRow;
        pagination.totalPage = data.totalPage;
      } else {
        informationList.value = [];
        pagination.total = 0;
        pagination.totalPage = 0;
      }
    } catch (err) {
      informationList.value = [];
      pagination.total = 0;
      pagination.totalPage = 0;
    } finally {
      setLoading(false);
    }
  };

  const searchData = () => {
    pagination.current = 1;
    fetchData();
  };

  const handleTypeChange = (val: any) => {
    selectedType.value = val;
    if (val) {
      condition.value.types = [val];
      if (val === 'eqp') {
        loadCategories();
      } else {
        condition.value.category = undefined;
        condition.value.subCategory = undefined;
      }
    } else {
      condition.value.types = [];
      condition.value.category = undefined;
      condition.value.subCategory = undefined;
    }
    searchData();
  };

  const handleTypeClear = () => {
    handleTypeChange(undefined);
  };

  const handleCategoryChange = () => {
    condition.value.subCategory = undefined;
    searchData();
  };

  const handleSubCategoryChange = () => {
    searchData();
  };

  const onPageChange = (current: number) => {
    pagination.current = current;
    jumpPage.value = current;
    fetchData();
  };

  const onPageSizeChange = (pageSize: number) => {
    pagination.pageSize = pageSize;
    pagination.current = 1;
    jumpPage.value = 1;
    fetchData();
  };

  const handleJumpPage = () => {
    if (jumpPage.value > 0 && jumpPage.value <= pagination.totalPage) {
      pagination.current = jumpPage.value;
      fetchData();
    }
  };

  const handleRowClick = async (record: InformationResult) => {
    selectedRecord.value = record;

    if (record.type === 'Eqp') {
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
        emit('select', record);
        visibleModel.value = false;
      }
    } else {
      emit('select', record);
      visibleModel.value = false;
    }
  };

  const handleEquipEditorSubmit = (data: GiveForm) => {
    const result = {
      ...selectedRecord.value,
      ...data,
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
    visibleModel.value = false;
  };

  watch(
    () => props.visible,
    (val) => {
      if (val) {
        condition.value.types = [];
        selectedType.value = undefined;
        condition.value.category = undefined;
        condition.value.subCategory = undefined;
        condition.value.filter = '';
        informationList.value = [];
        pagination.total = 0;
        pagination.totalPage = 0;
        selectedRecord.value = null;
        jumpPage.value = 1;

        if (props.initialId) {
          condition.value.filter = props.initialId.toString();
          // 搜索所有类型
          condition.value.types = [];
          searchData();
        }
      }
    }
  );
</script>

<style scoped>
  .filter-container {
    display: flex;
    flex-wrap: wrap;
    gap: 8px;
    margin-bottom: 16px;
  }
  .pagination-container {
    display: flex;
    flex-direction: column;
    align-items: center;
    margin-top: 16px;
  }
  .pagination-controls {
    display: flex;
    justify-content: space-between;
    width: 100%;
    margin-top: 8px;
    align-items: center;
  }
  .controls-right {
    display: flex;
    align-items: center;
  }
  .total-text {
    color: var(--color-text-3);
    font-size: 12px;
  }
</style>
