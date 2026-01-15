<template>
  <a-modal
    :visible="visible"
    :title="$t('account.player.warp.title')"
    :ok-loading="loading"
    :ok-text="$t('account.player.warp.submit')"
    @cancel="handleCancel"
    @before-ok="handleOk"
  >
    <a-tabs default-active-key="search">
      <a-tab-pane key="search" :title="$t('account.player.warp.search')">
        <a-input-search
          v-model="searchText"
          :placeholder="$t('account.player.warp.placeholder')"
          :loading="searchLoading"
          :disabled="searchLoading"
          allow-clear
          @search="handleSearch"
          @input="handleInput"
          @press-enter="handleSearch"
        />

        <div
          v-if="searchLoading"
          style="
            display: flex;
            flex-direction: column;
            align-items: center;
            justify-content: center;
            padding: 40px 0;
          "
        >
          <a-spin :size="40" />
          <div
            style="
              margin-top: 20px;
              font-size: 16px;
              font-weight: 500;
              color: var(--color-text-2);
            "
          >
            {{ $t('account.player.warp.loading.title') }}
          </div>
          <div
            style="margin-top: 8px; font-size: 13px; color: var(--color-text-3)"
          >
            {{ $t('account.player.warp.loading.desc') }}
          </div>
        </div>

        <template v-else>
          <div v-if="selectedMapInfo" style="margin-top: 10px">
            <a-alert type="success" style="margin-bottom: 10px">
              {{ $t('account.player.warp.current') }}：{{
                selectedMapInfo.name
              }}
              [{{ selectedMapInfo.id }}]
            </a-alert>
          </div>
          <div v-if="searchResults.length > 0" class="list-container">
            <a-list :scrollbar="true">
              <a-list-item
                v-for="item in searchResults"
                :key="item.id"
                :class="{ 'selected-item': selectedMapId === item.id }"
                @click="selectMap(item)"
              >
                <a-list-item-meta
                  :title="`${item.name} [${item.id}]`"
                  :description="item.desc"
                />
              </a-list-item>
            </a-list>
          </div>
          <div
            v-else-if="searchText && !selectedMapInfo"
            style="margin-top: 40px; text-align: center"
          >
            <a-empty :description="$t('account.player.warp.empty.desc')" />
          </div>
        </template>
      </a-tab-pane>

      <a-tab-pane key="zone" :title="$t('account.player.warp.zone')">
        <div style="margin-bottom: 10px">
          <a-select
            v-model="selectedStreet"
            :placeholder="$t('account.player.warp.zone.street')"
            :loading="loadingStreetNames"
            :filter-option="filterOption"
            allow-search
            @change="handleStreetChange"
          >
            <a-option
              v-for="street in streetNames"
              :key="street"
              :value="street"
            >
              {{ street }}
            </a-option>
          </a-select>
        </div>
        <div style="margin-bottom: 10px">
          <a-select
            v-model="selectedMapId"
            :placeholder="$t('account.player.warp.zone.map')"
            :disabled="!selectedStreet"
            :loading="loadingMapsInStreet"
            :filter-option="filterMapOption"
            allow-search
            @change="handleZoneMapChange"
          >
            <a-option
              v-for="map in mapsInStreet"
              :key="map.id"
              :value="map.id"
              :label="`${map.name} [${map.id}]`"
            >
              {{ map.name }} [{{ map.id }}]
            </a-option>
          </a-select>
        </div>
        <div v-if="selectedMapInfo" style="margin-top: 10px">
          <a-alert type="success" style="margin-bottom: 10px">
            {{ $t('account.player.warp.current') }}：{{
              selectedMapInfo.name
            }}
            [{{ selectedMapInfo.id }}]
          </a-alert>
          <a-descriptions :column="1" bordered>
            <a-descriptions-item :label="$t('account.player.warp.mapName')">
              {{ selectedMapInfo.name }}
            </a-descriptions-item>
            <a-descriptions-item :label="$t('account.player.warp.mapId')">
              {{ selectedMapInfo.id }}
            </a-descriptions-item>
            <a-descriptions-item :label="$t('account.player.warp.desc')">
              {{ selectedMapInfo.desc }}
            </a-descriptions-item>
          </a-descriptions>
          <div style="margin-top: 10px; text-align: right">
            <a-button
              type="outline"
              size="small"
              @click="addToFavorites(selectedMapInfo)"
            >
              <template #icon><icon-star /></template>
              {{ $t('account.player.warp.addToFavorites') }}
            </a-button>
          </div>
        </div>
      </a-tab-pane>

      <a-tab-pane key="favorites" :title="$t('account.player.warp.favorites')">
        <div v-if="selectedMapInfo" style="margin-bottom: 10px">
          <a-alert type="success">
            {{ $t('account.player.warp.current') }}：{{
              selectedMapInfo.name
            }}
            [{{ selectedMapInfo.id }}]
          </a-alert>
        </div>
        <div class="list-container">
          <a-list :scrollbar="true">
            <a-list-item
              v-for="map in favoriteMaps"
              :key="map.id"
              :class="{ 'selected-item': selectedMapId === map.id }"
            >
              <a-list-item-meta
                :title="`${map.name} [${map.id}]`"
                :description="map.desc"
              />
              <template #actions>
                <a-button type="primary" size="small" @click="selectMap(map)">
                  {{ $t('account.player.warp.select') }}
                </a-button>
                <a-button
                  status="danger"
                  size="small"
                  @click="removeFromFavorites(map.id)"
                >
                  <template #icon><icon-delete /></template>
                </a-button>
              </template>
            </a-list-item>
            <template #empty>
              <a-empty
                :description="$t('account.player.warp.emptyFavorites')"
              />
            </template>
          </a-list>
        </div>
      </a-tab-pane>

      <a-tab-pane key="history" :title="$t('account.player.warp.history')">
        <div style="text-align: right; margin-bottom: 10px">
          <a-button size="small" status="danger" @click="clearHistory">
            {{ $t('account.player.warp.clearHistory') }}
          </a-button>
        </div>
        <div v-if="selectedMapInfo" style="margin-bottom: 10px">
          <a-alert type="success">
            {{ $t('account.player.warp.current') }}：{{
              selectedMapInfo.name
            }}
            [{{ selectedMapInfo.id }}]
          </a-alert>
        </div>
        <div class="list-container">
          <a-list :scrollbar="true">
            <a-list-item
              v-for="map in historyMaps"
              :key="map.id"
              :class="{ 'selected-item': selectedMapId === map.id }"
            >
              <a-list-item-meta
                :title="`${map.name} [${map.id}]`"
                :description="map.desc"
              />
              <template #actions>
                <a-button type="primary" size="small" @click="selectMap(map)">
                  {{ $t('account.player.warp.select') }}
                </a-button>
                <a-button
                  status="danger"
                  size="small"
                  @click="removeFromHistory(map.id)"
                >
                  <template #icon><icon-delete /></template>
                </a-button>
              </template>
            </a-list-item>
            <template #empty>
              <a-empty :description="$t('account.player.warp.emptyHistory')" />
            </template>
          </a-list>
        </div>
      </a-tab-pane>
    </a-tabs>
  </a-modal>
</template>

<script setup lang="ts">
  import { ref, onMounted, watch } from 'vue';
  import {
    informationSearch,
    getStreetNames,
    getMapsByStreetName,
    InformationResult,
    InformationSearch as SearchParams,
  } from '@/api/information';
  import { Message } from '@arco-design/web-vue';
  import { useI18n } from 'vue-i18n';

  const { t } = useI18n();

  const props = defineProps<{
    visible: boolean;
    loading: boolean;
  }>();

  const emit = defineEmits(['update:visible', 'submit']);

  const searchLoading = ref(false);
  const searchResults = ref<InformationResult[]>([]);
  const selectedMapId = ref<number | undefined>(undefined);
  const selectedMapInfo = ref<InformationResult | null>(null);
  const searchText = ref('');
  let searchTimer: any = null;

  const favoriteMaps = ref<InformationResult[]>([]);
  const historyMaps = ref<InformationResult[]>([]);

  // 区域查找相关
  const streetNames = ref<string[]>([]);
  const loadingStreetNames = ref(false);
  const selectedStreet = ref<string | undefined>(undefined);
  const mapsInStreet = ref<InformationResult[]>([]);
  const loadingMapsInStreet = ref(false);

  const selectMap = (map: InformationResult) => {
    selectedMapId.value = map.id;
    selectedMapInfo.value = map;
  };

  // 加载本地存储
  onMounted(() => {
    const favs = localStorage.getItem('warp_favorite_maps');
    if (favs) favoriteMaps.value = JSON.parse(favs);

    const hist = localStorage.getItem('warp_history_maps');
    if (hist) historyMaps.value = JSON.parse(hist);
  });

  // 监听 visible 变化，首次打开时加载区域列表
  watch(
    () => props.visible,
    async (val) => {
      if (val && streetNames.value.length === 0) {
        loadingStreetNames.value = true;
        try {
          const { data } = await getStreetNames();
          // @ts-ignore
          streetNames.value = data;
        } catch (err) {
          // ignore
        } finally {
          loadingStreetNames.value = false;
        }
      }
    }
  );

  const handleSearch = async (value?: string | any) => {
    // 如果是定时器触发的搜索，value可能为空，使用searchText.value
    // 修复：如果是事件对象（如按回车触发），则使用 searchText.value
    const query = typeof value === 'string' ? value : searchText.value;
    if (!query) return;

    // 清除之前的定时器，避免重复搜索
    if (searchTimer) {
      clearTimeout(searchTimer);
      searchTimer = null;
    }

    searchLoading.value = true;
    // 清空之前的结果
    searchResults.value = [];
    selectedMapId.value = undefined;
    selectedMapInfo.value = null;

    try {
      const params: SearchParams = { types: ['map'], filter: query };
      const { data } = await informationSearch(params);
      // @ts-ignore
      // 兼容分页返回结构
      if (data.records) {
        // @ts-ignore
        searchResults.value = data.records;
      } else {
        // @ts-ignore
        searchResults.value = data;
      }
    } finally {
      searchLoading.value = false;
    }
  };

  const handleInput = (value: string) => {
    if (searchTimer) {
      clearTimeout(searchTimer);
    }
    if (!value) {
      searchResults.value = [];
      return;
    }
    searchTimer = setTimeout(() => {
      handleSearch(value);
    }, 1500);
  };

  const handleStreetChange = async (value: any) => {
    selectedMapId.value = undefined;
    selectedMapInfo.value = null;
    mapsInStreet.value = [];
    if (!value) return;

    loadingMapsInStreet.value = true;
    try {
      const { data } = await getMapsByStreetName(value);
      // @ts-ignore
      mapsInStreet.value = data;
    } finally {
      loadingMapsInStreet.value = false;
    }
  };

  const handleZoneMapChange = (value: any) => {
    const map = mapsInStreet.value.find((item) => item.id === value);
    if (map) selectMap(map);
  };

  const filterOption = (inputValue: string, option: any) => {
    return option.label.toLowerCase().includes(inputValue.toLowerCase());
  };

  const filterMapOption = (inputValue: string, option: any) => {
    return option.label.toLowerCase().includes(inputValue.toLowerCase());
  };

  const addToFavorites = (map: InformationResult) => {
    if (favoriteMaps.value.some((m) => m.id === map.id)) {
      Message.warning(t('account.player.warp.msg.exist'));
      return;
    }
    favoriteMaps.value.push(map);
    localStorage.setItem(
      'warp_favorite_maps',
      JSON.stringify(favoriteMaps.value)
    );
    Message.success(t('account.player.warp.msg.success'));
  };

  const removeFromFavorites = (id: number) => {
    favoriteMaps.value = favoriteMaps.value.filter((m) => m.id !== id);
    localStorage.setItem(
      'warp_favorite_maps',
      JSON.stringify(favoriteMaps.value)
    );
  };

  const addToHistory = (map: InformationResult) => {
    const newHistory = historyMaps.value.filter((m) => m.id !== map.id);
    newHistory.unshift(map);
    if (newHistory.length > 10) newHistory.pop();
    historyMaps.value = newHistory;
    localStorage.setItem(
      'warp_history_maps',
      JSON.stringify(historyMaps.value)
    );
  };

  const removeFromHistory = (id: number) => {
    historyMaps.value = historyMaps.value.filter((m) => m.id !== id);
    localStorage.setItem(
      'warp_history_maps',
      JSON.stringify(historyMaps.value)
    );
  };

  const clearHistory = () => {
    historyMaps.value = [];
    localStorage.removeItem('warp_history_maps');
  };

  const handleCancel = () => {
    emit('update:visible', false);
    selectedMapId.value = undefined;
    selectedMapInfo.value = null;
    searchResults.value = [];
    selectedStreet.value = undefined;
    mapsInStreet.value = [];
    searchText.value = '';
    if (searchTimer) {
      clearTimeout(searchTimer);
      searchTimer = null;
    }
  };

  const handleOk = () => {
    if (!selectedMapId.value) {
      Message.warning(t('account.player.warp.msg.select'));
      return false;
    }
    if (selectedMapInfo.value) {
      addToHistory(selectedMapInfo.value);
    }
    emit('submit', selectedMapId.value);
    return true;
  };
</script>

<style scoped>
  .selected-item {
    background-color: var(--color-primary-light-1);
  }

  .list-container {
    margin-top: 10px;
    max-height: 300px;
    overflow-y: auto;
    padding-right: 4px;
  }

  /* 自定义滚动条样式 */
  .list-container::-webkit-scrollbar {
    width: 6px;
    height: 6px;
    display: none;
  }

  .list-container:hover::-webkit-scrollbar {
    display: block;
  }

  .list-container::-webkit-scrollbar-thumb {
    border-radius: 3px;
    background-color: var(--color-text-4);
  }

  .list-container::-webkit-scrollbar-track {
    background-color: transparent;
  }
</style>
