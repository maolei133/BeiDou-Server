<template>
  <a-modal
    :visible="visible"
    :title="$t('account.player.edit.title')"
    width="800px"
    @cancel="handleCancel"
    @before-ok="handleBeforeOk"
  >
    <a-tabs default-active-key="1">
      <a-tab-pane key="1" :title="$t('account.player.edit.tab.basic')">
        <a-form
          :model="form"
          :label-col-props="{ span: 6 }"
          :wrapper-col-props="{ span: 18 }"
        >
          <a-row :gutter="16">
            <a-col :span="12">
              <a-form-item field="name" :label="$t('account.player.name')">
                <a-input v-model="form.name" />
              </a-form-item>
            </a-col>
            <a-col :span="12">
              <a-form-item field="level" :label="$t('account.player.level')">
                <a-input-number v-model="form.level" />
              </a-form-item>
            </a-col>
            <a-col :span="12">
              <a-form-item field="exp" :label="$t('account.player.exp')">
                <a-input-number v-model="form.exp" />
              </a-form-item>
            </a-col>
            <a-col :span="12">
              <a-form-item field="job" :label="$t('account.player.job')">
                <a-select
                  v-model="form.job"
                  :loading="loadingJobs"
                  allow-search
                  :filter-option="filterJobOption"
                >
                  <a-option
                    v-for="job in jobList"
                    :key="job.id"
                    :value="job.id"
                    :label="`${job.name} (${job.id})`"
                  />
                </a-select>
              </a-form-item>
            </a-col>
            <a-col :span="12">
              <a-form-item field="fame" :label="$t('account.player.fame')">
                <a-input-number v-model="form.fame" />
              </a-form-item>
            </a-col>
            <a-col :span="12">
              <a-form-item field="ap" :label="$t('account.player.ap')">
                <a-input-number v-model="form.ap" />
              </a-form-item>
            </a-col>
            <a-col :span="12">
              <a-form-item field="sp" :label="$t('account.player.sp')">
                <a-input v-model="form.sp" placeholder="1,0,0..." />
              </a-form-item>
            </a-col>
            <a-col :span="12">
              <a-form-item field="gender" :label="$t('account.player.gender')">
                <a-select v-model="form.gender">
                  <a-option :value="0">{{
                    $t('account.list.column.gender.male')
                  }}</a-option>
                  <a-option :value="1">{{
                    $t('account.list.column.gender.female')
                  }}</a-option>
                </a-select>
              </a-form-item>
            </a-col>
            <a-col :span="12">
              <a-form-item field="gm" :label="$t('account.player.gm')">
                <a-input-number v-model="form.gm" />
              </a-form-item>
            </a-col>
            <a-col :span="12">
              <a-form-item
                field="buddyCapacity"
                :label="$t('account.player.buddyCapacity')"
              >
                <a-input-number v-model="form.buddyCapacity" />
              </a-form-item>
            </a-col>
          </a-row>
        </a-form>
      </a-tab-pane>
      <a-tab-pane key="2" :title="$t('account.player.edit.tab.stats')">
        <a-form
          :model="form"
          :label-col-props="{ span: 6 }"
          :wrapper-col-props="{ span: 18 }"
        >
          <a-row :gutter="16">
            <a-col :span="12">
              <a-form-item field="str" :label="$t('account.player.form.str')">
                <a-input-number v-model="form.str" />
              </a-form-item>
            </a-col>
            <a-col :span="12">
              <a-form-item field="dex" :label="$t('account.player.form.dex')">
                <a-input-number v-model="form.dex" />
              </a-form-item>
            </a-col>
            <a-col :span="12">
              <a-form-item
                field="intAttr"
                :label="$t('account.player.form.int')"
              >
                <a-input-number v-model="form.intAttr" />
              </a-form-item>
            </a-col>
            <a-col :span="12">
              <a-form-item field="luk" :label="$t('account.player.form.luk')">
                <a-input-number v-model="form.luk" />
              </a-form-item>
            </a-col>
            <a-col :span="12">
              <a-form-item field="hp" :label="$t('account.player.form.hp')">
                <a-input-number v-model="form.hp" />
              </a-form-item>
            </a-col>
            <a-col :span="12">
              <a-form-item field="maxHp" :label="$t('account.player.maxHp')">
                <a-input-number v-model="form.maxHp" />
              </a-form-item>
            </a-col>
            <a-col :span="12">
              <a-form-item field="mp" :label="$t('account.player.form.mp')">
                <a-input-number v-model="form.mp" />
              </a-form-item>
            </a-col>
            <a-col :span="12">
              <a-form-item field="maxMp" :label="$t('account.player.maxMp')">
                <a-input-number v-model="form.maxMp" />
              </a-form-item>
            </a-col>
          </a-row>
        </a-form>
      </a-tab-pane>
      <a-tab-pane key="3" :title="$t('account.player.edit.tab.look')">
        <a-form
          :model="form"
          :label-col-props="{ span: 6 }"
          :wrapper-col-props="{ span: 18 }"
        >
          <a-row :gutter="16">
            <a-col :span="12">
              <a-form-item field="face" :label="$t('account.player.face')">
                <div class="selector-trigger" @click="openFaceSelector">
                  <div v-if="form.face" class="selected-content">
                    <div class="item-image">
                      <img :src="getIconUrl('item', form.face)" alt="" />
                    </div>
                    <div class="item-info">
                      <div class="item-name" :title="getFaceName(form.face)">
                        {{ getFaceName(form.face) }}
                      </div>
                      <div class="item-id">{{ form.face }}</div>
                    </div>
                  </div>
                  <span v-else class="placeholder">{{
                    $t('account.player.warp.select')
                  }}</span>
                </div>
              </a-form-item>
            </a-col>
            <a-col :span="12">
              <a-form-item field="hair" :label="$t('account.player.hair')">
                <div class="selector-trigger" @click="openHairSelector">
                  <div v-if="form.hair" class="selected-content">
                    <div class="item-image">
                      <img :src="getIconUrl('item', form.hair)" alt="" />
                    </div>
                    <div class="item-info">
                      <div class="item-name" :title="getHairName(form.hair)">
                        {{ getHairName(form.hair) }}
                      </div>
                      <div class="item-id">{{ form.hair }}</div>
                    </div>
                  </div>
                  <span v-else class="placeholder">{{
                    $t('account.player.warp.select')
                  }}</span>
                </div>
              </a-form-item>
            </a-col>
            <a-col :span="12">
              <a-form-item field="skinColor" :label="$t('account.player.skin')">
                <a-select v-model="form.skinColor" :loading="loadingSkins">
                  <a-option
                    v-for="skin in skinList"
                    :key="skin.id"
                    :value="skin.id"
                    :label="`${$t('account.player.skin.' + skin.id)} (${
                      skin.id
                    })`"
                  />
                </a-select>
              </a-form-item>
            </a-col>
          </a-row>
        </a-form>
      </a-tab-pane>
      <a-tab-pane key="4" :title="$t('account.player.edit.tab.currency')">
        <a-form
          :model="form"
          :label-col-props="{ span: 6 }"
          :wrapper-col-props="{ span: 18 }"
        >
          <a-row :gutter="16">
            <a-col :span="12">
              <a-form-item field="meso" :label="$t('account.player.meso')">
                <a-input-number v-model="form.meso" />
              </a-form-item>
            </a-col>
            <a-col :span="12">
              <a-form-item
                field="merchantMesos"
                :label="$t('account.player.merchantMesos')"
              >
                <a-input-number v-model="form.merchantMesos" />
              </a-form-item>
            </a-col>
            <a-col :span="12">
              <a-form-item
                field="gachaExp"
                :label="$t('account.player.gachaExp')"
              >
                <a-input-number v-model="form.gachaExp" />
              </a-form-item>
            </a-col>
            <a-col :span="12">
              <a-form-item
                field="nxCredit"
                :label="$t('account.player.nxCredit')"
              >
                <a-input-number v-model="form.nxCredit" />
              </a-form-item>
            </a-col>
            <a-col :span="12">
              <a-form-item
                field="maplePoint"
                :label="$t('account.player.maplePoint')"
              >
                <a-input-number v-model="form.maplePoint" />
              </a-form-item>
            </a-col>
            <a-col :span="12">
              <a-form-item
                field="nxPrepaid"
                :label="$t('account.player.nxPrepaid')"
              >
                <a-input-number v-model="form.nxPrepaid" />
              </a-form-item>
            </a-col>
          </a-row>
        </a-form>
      </a-tab-pane>
      <a-tab-pane key="5" :title="$t('account.player.edit.tab.inventory')">
        <a-form
          :model="form"
          :label-col-props="{ span: 6 }"
          :wrapper-col-props="{ span: 18 }"
        >
          <a-row :gutter="16">
            <a-col :span="12">
              <a-form-item
                field="equipSlots"
                :label="$t('account.player.equipSlots')"
              >
                <a-input-number v-model="form.equipSlots" />
              </a-form-item>
            </a-col>
            <a-col :span="12">
              <a-form-item
                field="useSlots"
                :label="$t('account.player.useSlots')"
              >
                <a-input-number v-model="form.useSlots" />
              </a-form-item>
            </a-col>
            <a-col :span="12">
              <a-form-item
                field="setupSlots"
                :label="$t('account.player.setupSlots')"
              >
                <a-input-number v-model="form.setupSlots" />
              </a-form-item>
            </a-col>
            <a-col :span="12">
              <a-form-item
                field="etcSlots"
                :label="$t('account.player.etcSlots')"
              >
                <a-input-number v-model="form.etcSlots" />
              </a-form-item>
            </a-col>
          </a-row>
        </a-form>
      </a-tab-pane>
      <a-tab-pane key="6" :title="$t('account.player.edit.tab.location')">
        <a-form
          :model="form"
          :label-col-props="{ span: 6 }"
          :wrapper-col-props="{ span: 18 }"
        >
          <a-row :gutter="16">
            <a-col :span="12">
              <a-form-item field="map" :label="$t('account.player.map')">
                <a-input-number v-model="form.map" />
              </a-form-item>
            </a-col>
            <a-col :span="12">
              <a-form-item
                field="spawnPoint"
                :label="$t('account.player.spawnPoint')"
              >
                <a-input-number v-model="form.spawnPoint" />
              </a-form-item>
            </a-col>
          </a-row>
        </a-form>
      </a-tab-pane>
      <a-tab-pane key="7" :title="$t('account.player.edit.tab.mount')">
        <a-form
          :model="form"
          :label-col-props="{ span: 6 }"
          :wrapper-col-props="{ span: 18 }"
        >
          <a-row :gutter="16">
            <a-col :span="12">
              <a-form-item
                field="mountLevel"
                :label="$t('account.player.mountLevel')"
              >
                <a-input-number v-model="form.mountLevel" />
              </a-form-item>
            </a-col>
            <a-col :span="12">
              <a-form-item
                field="mountExp"
                :label="$t('account.player.mountExp')"
              >
                <a-input-number v-model="form.mountExp" />
              </a-form-item>
            </a-col>
            <a-col :span="12">
              <a-form-item
                field="mountTiredness"
                :label="$t('account.player.mountTiredness')"
              >
                <a-input-number v-model="form.mountTiredness" />
              </a-form-item>
            </a-col>
          </a-row>
        </a-form>
      </a-tab-pane>
    </a-tabs>

    <ImageSelector
      v-model:visible="faceSelectorVisible"
      type="face"
      :title="$t('account.player.face')"
      :default-id="form.face"
      @select="handleFaceSelect"
    />

    <ImageSelector
      v-model:visible="hairSelectorVisible"
      type="hair"
      :title="$t('account.player.hair')"
      :default-id="form.hair"
      @select="handleHairSelect"
    />
  </a-modal>
</template>

<script setup lang="ts">
  import { ref, watch, PropType, onMounted } from 'vue';
  import {
    OnlinePlayer,
    UpdatePlayerForm,
    updatePlayer,
    getPlayerDetail,
  } from '@/api/player';
  import {
    getJobs,
    getSkinColors,
    informationSearch,
    InformationResult,
  } from '@/api/information';
  import { Message } from '@arco-design/web-vue';
  import { useI18n } from 'vue-i18n';
  import { getIconUrl } from '@/utils/mapleStoryAPI';
  import ImageSelector from '@/components/ImageSelector/index.vue';

  const props = defineProps({
    visible: {
      type: Boolean,
      default: false,
    },
    player: {
      type: Object as PropType<OnlinePlayer | null>,
      default: null,
    },
  });

  const emit = defineEmits(['update:visible', 'success']);
  const { t } = useI18n();

  const form = ref<UpdatePlayerForm>({
    id: 0,
  });

  const jobList = ref<InformationResult[]>([]);
  const loadingJobs = ref(false);
  const skinList = ref<InformationResult[]>([]);
  const loadingSkins = ref(false);

  // 缓存已加载的名称，用于回显
  const faceNameMap = ref<Record<number, string>>({});
  const hairNameMap = ref<Record<number, string>>({});

  const faceSelectorVisible = ref(false);
  const hairSelectorVisible = ref(false);

  const fetchJobs = async () => {
    loadingJobs.value = true;
    try {
      const { data } = await getJobs();
      jobList.value = data;
    } catch (error) {
      Message.error('获取职业列表失败');
    } finally {
      loadingJobs.value = false;
    }
  };

  const fetchSkins = async () => {
    loadingSkins.value = true;
    try {
      const { data } = await getSkinColors();
      skinList.value = data;
    } catch (error) {
      Message.error('获取肤色列表失败');
    } finally {
      loadingSkins.value = false;
    }
  };

  // 预加载名称
  const loadItemName = async (type: 'face' | 'hair', id: number) => {
    if (!id) return;
    try {
      const { data } = await informationSearch({
        types: [type],
        filter: String(id),
        filterType: 1, // ID匹配
        fullMatch: true,
      });
      // 兼容分页返回结构
      // @ts-ignore
      const records = data.records || data;
      if (records && records.length > 0) {
        if (type === 'face') {
          faceNameMap.value[id] = records[0].name;
        } else {
          hairNameMap.value[id] = records[0].name;
        }
      }
    } catch (error) {
      // ignore
    }
  };

  const getFaceName = (id: number) => {
    return faceNameMap.value[id] || '';
  };

  const getHairName = (id: number) => {
    return hairNameMap.value[id] || '';
  };

  const openFaceSelector = () => {
    faceSelectorVisible.value = true;
  };

  const openHairSelector = () => {
    hairSelectorVisible.value = true;
  };

  const handleFaceSelect = (id: number, item: InformationResult) => {
    form.value.face = id;
    if (item) {
      faceNameMap.value[id] = item.name;
    }
  };

  const handleHairSelect = (id: number, item: InformationResult) => {
    form.value.hair = id;
    if (item) {
      hairNameMap.value[id] = item.name;
    }
  };

  onMounted(() => {
    fetchJobs();
    fetchSkins();
  });

  const filterJobOption = (inputValue: string, option: any) => {
    return (
      option.label.toLowerCase().includes(inputValue.toLowerCase()) ||
      String(option.value).includes(inputValue)
    );
  };

  watch(
    () => props.player,
    async (newVal) => {
      if (newVal) {
        try {
          const { data } = await getPlayerDetail(newVal.id);
          // eslint-disable-next-line @typescript-eslint/no-explicit-any
          const detail = data as any;
          form.value = {
            id: detail.id,
            name: detail.name,
            level: detail.level,
            exp: detail.exp,
            job: detail.job,
            str: detail.str,
            dex: detail.dex,
            intAttr: detail.intAttr || detail.int,
            luk: detail.luk,
            hp: detail.hp,
            maxHp: detail.maxHp,
            mp: detail.mp,
            maxMp: detail.maxMp,
            ap: detail.ap,
            sp: detail.sp,
            fame: detail.fame,
            meso: detail.meso,
            gm: detail.gm,
            face: detail.face,
            hair: detail.hair,
            skinColor: detail.skinColor,
            gender: detail.gender,
            nxCredit: detail.nxCredit,
            maplePoint: detail.maplePoint,
            nxPrepaid: detail.nxPrepaid,
            equipSlots: detail.equipSlots,
            useSlots: detail.useSlots,
            setupSlots: detail.setupSlots,
            etcSlots: detail.etcSlots,
            buddyCapacity: detail.buddyCapacity,
            merchantMesos: detail.merchantMesos,
            gachaExp: detail.gachaExp,
            map: detail.map,
            spawnPoint: detail.spawnPoint,
            mountLevel: detail.mountLevel,
            mountExp: detail.mountExp,
            mountTiredness: detail.mountTiredness,
          };

          // 初始化加载当前脸型和发型信息，以便显示
          if (detail.face) {
            loadItemName('face', detail.face);
          }
          if (detail.hair) {
            loadItemName('hair', detail.hair);
          }
        } catch (error) {
          Message.error('获取角色详情失败');
        }
      }
    },
    { immediate: true }
  );

  const handleCancel = () => {
    emit('update:visible', false);
  };

  const handleBeforeOk = async () => {
    try {
      await updatePlayer(form.value);
      Message.success(t('message.success'));
      emit('success');
      return true;
    } catch (error) {
      return false;
    }
  };
</script>

<style scoped lang="less">
  .selector-trigger {
    width: 100%;
    height: 64px; /* 增加高度以容纳图片和两行文字 */
    padding: 8px 12px;
    border: 1px solid var(--color-border-2);
    border-radius: var(--border-radius-small);
    background-color: var(--color-bg-2);
    cursor: pointer;
    display: flex;
    align-items: center;
    transition: all 0.1s cubic-bezier(0, 0, 1, 1);

    &:hover {
      border-color: rgb(var(--primary-6));
      background-color: var(--color-fill-2);
    }

    .placeholder {
      color: var(--color-text-3);
    }

    .selected-content {
      display: flex;
      align-items: center;
      width: 100%;

      .item-image {
        width: 48px;
        height: 48px;
        margin-right: 12px;
        display: flex;
        align-items: center;
        justify-content: center;
        flex-shrink: 0;

        img {
          max-width: 100%;
          max-height: 100%;
          object-fit: contain;
        }
      }

      .item-info {
        flex: 1;
        overflow: hidden;
        display: flex;
        flex-direction: column;
        justify-content: center;

        .item-name {
          font-size: 14px;
          font-weight: 500;
          overflow: hidden;
          text-overflow: ellipsis;
          white-space: nowrap;
          margin-bottom: 2px;
        }

        .item-id {
          font-size: 12px;
          color: var(--color-text-3);
        }
      }
    }
  }
</style>
