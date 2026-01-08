<template>
  <div class="container" :loading="true">
    <Breadcrumb />
    <a-card class="general-card" :title="$t('menu.account.player')">
      <!-- 搜索表单 -->
      <a-form :model="filterForm" class="a-from-keyword">
        <a-row :gutter="16">
          <a-col :span="6">
            <a-form-item :label="$t('account.player.id')">
              <a-input-number v-model="filterForm.id" />
            </a-form-item>
          </a-col>
          <a-col :span="6">
            <a-form-item :label="$t('account.player.name')">
              <a-input v-model="filterForm.name" />
            </a-form-item>
          </a-col>
          <a-col :span="6">
            <a-form-item :label="$t('account.player.mapId')">
              <a-input-number v-model="filterForm.map" />
            </a-form-item>
          </a-col>
          <a-col :span="6">
            <a-form-item :label="$t('account.player.status')">
              <a-select
                v-model="filterForm.status"
                :placeholder="$t('account.player.status.placeholder')"
              >
                <a-option :value="0">{{
                  $t('account.player.status.all')
                }}</a-option>
                <a-option :value="1">{{
                  $t('account.player.status.online')
                }}</a-option>
                <a-option :value="2">{{
                  $t('account.player.status.offline')
                }}</a-option>
              </a-select>
            </a-form-item>
          </a-col>
        </a-row>
      </a-form>
      <a-space>
        <a-button type="primary" @click="loadData()">
          <template #icon>
            <icon-search />
          </template>
          {{ $t('button.load') }}
        </a-button>
        <a-button @click="resetClick">
          <template #icon>
            <icon-refresh />
          </template>
          {{ $t('button.reset') }}
        </a-button>
      </a-space>
      <a-divider />
      <!-- 操作按钮 -->
      <a-row style="margin-bottom: 16px">
        <a-col>
          <a-space>
            <a-button type="primary" @click="refreshClick">
              <template #icon>
                <icon-refresh />
              </template>
              {{ $t('button.refresh') }}
            </a-button>
            <a-dropdown @select="handleGlobalAction">
              <a-button type="primary">
                {{ $t('account.player.button.globalAction') }} <icon-down />
              </a-button>
              <template #content>
                <a-doption value="warp">{{
                  $t('account.player.button.globalWarp')
                }}</a-doption>
                <a-doption value="give">{{
                  $t('account.player.button.globalGive')
                }}</a-doption>
              </template>
            </a-dropdown>
          </a-space>
        </a-col>
      </a-row>

      <!-- 桌面端表格 -->
      <a-table
        v-if="!isMobile"
        row-key="id"
        :loading="loading"
        :data="tableData"
        column-resizable
        :pagination="false"
        :bordered="{ cell: true }"
      >
        <template #columns>
          <a-table-column
            :title="$t('account.player.channel')"
            data-index="channel"
            :width="70"
            align="center"
          />
          <a-table-column
            :title="$t('account.player.accountId')"
            :width="150"
            align="center"
          >
            <template #cell="{ record }">
              <router-link
                :to="{ name: 'AccountList', query: { id: record.accountId } }"
              >
                [ {{ record.accountId }} ] {{ record.accountName }}
              </router-link>
            </template>
          </a-table-column>
          <a-table-column
            :title="$t('account.player.id')"
            data-index="id"
            :width="80"
            align="center"
          />
          <a-table-column
            :title="$t('account.player.name')"
            data-index="name"
            :width="150"
            align="center"
          />
          <a-table-column
            :title="$t('account.player.gender')"
            :width="70"
            align="center"
          >
            <template #cell="{ record }">
              <span v-if="record.gender === 0">
                {{ $t('account.list.column.gender.male') }}
              </span>
              <span v-else-if="record.gender === 1">
                {{ $t('account.list.column.gender.female') }}
              </span>
              <span v-else>{{ $t('account.list.column.gender.other') }}</span>
            </template>
          </a-table-column>
          <a-table-column
            :title="$t('account.player.map')"
            :min-width="250"
            align="center"
            ellipsis
            tooltip
          >
            <template #cell="{ record }">
              <span style="white-space: nowrap">
                {{ record.mapName }} ({{ record.map }})
                <a-button type="text" @click="handleWarp(record)">
                  {{ $t('account.player.button.warp') }}
                </a-button>
              </span>
            </template>
          </a-table-column>
          <a-table-column
            :title="$t('account.player.job')"
            :width="180"
            align="center"
          >
            <template #cell="{ record }">
              {{ record.jobName }} ({{ record.job }})
            </template>
          </a-table-column>
          <a-table-column
            :title="$t('account.player.level')"
            data-index="level"
            :width="70"
            align="center"
          />
          <a-table-column
            :title="$t('account.player.fame')"
            data-index="fame"
            :width="70"
            align="center"
          />
          <a-table-column
            :title="$t('account.player.maxHp')"
            data-index="maxHp"
            :width="90"
            align="center"
          />
          <a-table-column
            :title="$t('account.player.maxMp')"
            data-index="maxMp"
            :width="90"
            align="center"
          />
          <a-table-column
            :title="$t('account.player.partyId')"
            data-index="partyId"
            :width="90"
            align="center"
          />
          <a-table-column
            :title="$t('account.player.guild')"
            :width="180"
            align="center"
          >
            <template #cell="{ record }">
              <span v-if="record.guildId > 0">
                {{ record.guildName }} ({{ record.guildId }})
              </span>
            </template>
          </a-table-column>
          <a-table-column
            v-if="filterForm.status === 1 || filterForm.status === 0"
            :title="$t('account.player.loginTime')"
            data-index="loginTime"
            :width="180"
            align="center"
          />
          <a-table-column
            v-if="filterForm.status === 1"
            :title="$t('account.player.onlineTime')"
            :width="120"
            align="center"
          >
            <template #cell="{ record }">
              {{ calculateOnlineTime(record.loginTime) }}
            </template>
          </a-table-column>
          <a-table-column
            v-if="filterForm.status === 2"
            :title="$t('account.player.lastLogoutTime')"
            data-index="lastLogoutTime"
            :width="180"
            align="center"
          />
          <a-table-column
            :title="$t('account.player.gm.level')"
            data-index="gm"
            :width="70"
            align="center"
          />
          <a-table-column :title="$t('account.list.column.operate')">
            <template #cell="{ record }">
              <a-space>
                <a-button type="text" size="mini" @click="editClick(record)">
                  {{ $t('account.player.button.edit') }}
                </a-button>
                <a-button type="text" size="mini" @click="giveClick(record)">
                  {{ $t('account.player.button.give') }}
                </a-button>
              </a-space>
            </template>
          </a-table-column>
        </template>
      </a-table>

      <!-- 移动端列表 -->
      <a-list v-else :data="tableData" :loading="loading">
        <template #item="{ item }">
          <a-list-item>
            <a-card :title="item.name" class="mobile-card">
              <template #extra>
                <a-space>
                  <a-button
                    type="primary"
                    size="mini"
                    @click="handleWarp(item)"
                  >
                    传送
                  </a-button>
                  <a-button size="mini" @click="editClick(item)">编辑</a-button>
                  <a-button size="mini" @click="giveClick(item)">发放</a-button>
                </a-space>
              </template>
              <a-descriptions
                :column="1"
                size="small"
                layout="inline-horizontal"
              >
                <a-descriptions-item :label="$t('account.player.accountId')">
                  <router-link
                    :to="{ name: 'AccountList', query: { id: item.accountId } }"
                  >
                    [ {{ item.accountId }} ] {{ item.accountName }}
                  </router-link>
                </a-descriptions-item>
                <a-descriptions-item :label="$t('account.player.id')">
                  {{ item.id }}
                </a-descriptions-item>
                <a-descriptions-item :label="$t('account.player.level')">
                  {{ item.level }}
                </a-descriptions-item>
                <a-descriptions-item :label="$t('account.player.map')">
                  {{ item.mapName }} ({{ item.map }})
                </a-descriptions-item>
                <a-descriptions-item :label="$t('account.player.job')">
                  {{ item.jobName }} ({{ item.job }})
                </a-descriptions-item>
                <a-descriptions-item :label="$t('account.player.maxHp')">
                  {{ item.maxHp }}
                </a-descriptions-item>
                <a-descriptions-item :label="$t('account.player.maxMp')">
                  {{ item.maxMp }}
                </a-descriptions-item>
                <a-descriptions-item :label="$t('account.player.partyId')">
                  {{ item.partyId }}
                </a-descriptions-item>
                <a-descriptions-item
                  v-if="item.guildId > 0"
                  :label="$t('account.player.guild')"
                >
                  {{ item.guildName }} ({{ item.guildId }})
                </a-descriptions-item>
                <a-descriptions-item
                  v-if="item.loginTime"
                  :label="$t('account.player.loginTime')"
                >
                  {{ item.loginTime }}
                </a-descriptions-item>
                <a-descriptions-item
                  v-if="item.loginTime && filterForm.status === 1"
                  :label="$t('account.player.onlineTime')"
                >
                  {{ calculateOnlineTime(item.loginTime) }}
                </a-descriptions-item>
                <a-descriptions-item
                  v-if="item.lastLogoutTime"
                  :label="$t('account.player.lastLogoutTime')"
                >
                  {{ item.lastLogoutTime }}
                </a-descriptions-item>
              </a-descriptions>
            </a-card>
          </a-list-item>
        </template>
      </a-list>

      <a-pagination
        style="margin-top: 20px"
        :total="total"
        :page-size="size"
        :current="page"
        show-total
        show-jumper
        show-page-size
        :page-size-options="[10, 20, 50, 100]"
        @change="pageChange"
        @page-size-change="pageSizeChange"
      />
    </a-card>

    <!-- 弹窗 -->
    <a-modal
      v-model:visible="giveFormVisible"
      :title="giveFormTitle"
      :ok-loading="loading"
      :mask-closable="false"
      :esc-to-close="false"
      :ok-text="$t('account.player.give')"
      :on-before-ok="submitClick"
    >
      <a-form :model="formData" class="form-aligned">
        <a-row :gutter="16">
          <a-col :span="24">
            <a-form-item
              v-if="formData.playerId !== 0"
              field="player"
              :label="$t('account.player.form.player')"
            >
              <a-input v-model="formData.player" disabled style="width: 100%" />
            </a-form-item>
            <a-form-item field="type" :label="$t('account.player.form.type')">
              <a-select
                v-model="formData.type"
                style="width: 100%"
                @change="handleTypeChange"
              >
                <a-option :value="0">{{
                  $t('account.player.nxCredit')
                }}</a-option>
                <a-option :value="1">{{
                  $t('account.player.nxPrepaid')
                }}</a-option>
                <a-option :value="2">{{
                  $t('account.player.maplePoint')
                }}</a-option>
                <a-option :value="3">{{ $t('account.player.mesos') }}</a-option>
                <a-option :value="4">{{ $t('account.player.exp') }}</a-option>
                <a-option :value="5">{{ $t('account.player.item') }}</a-option>
                <a-option :value="6">{{ $t('account.player.equip') }}</a-option>
                <a-option :value="7">{{
                  $t('account.player.expRate')
                }}</a-option>
                <a-option :value="8">{{
                  $t('account.player.mesosRate')
                }}</a-option>
                <a-option :value="9">{{
                  $t('account.player.dropRate')
                }}</a-option>
              </a-select>
            </a-form-item>
            <a-form-item
              v-if="formData.type === 5"
              field="id"
              :label="$t('account.player.form.id')"
            >
              <a-input-number
                v-model="formData.id"
                style="width: 100%"
                @blur="handleIdBlur"
              />
            </a-form-item>
            <a-form-item
              v-if="
                formData.type === 0 ||
                formData.type === 1 ||
                formData.type === 2 ||
                formData.type === 3 ||
                formData.type === 4 ||
                formData.type === 5
              "
              field="quantity"
              :label="$t('account.player.form.quantity')"
            >
              <a-input-number v-model="formData.quantity" style="width: 100%" />
            </a-form-item>
            <a-form-item
              v-if="
                formData.type === 7 ||
                formData.type === 8 ||
                formData.type === 9
              "
              field="rate"
              :label="$t('account.player.form.rate')"
              :rules="[
                {
                  required: true,
                  message: $t('account.player.form.rate.required'),
                },
                {
                  type: 'number',
                  min: 0,
                  message: $t('account.player.form.rate.type'),
                },
              ]"
            >
              <a-input-number v-model="formData.rate" style="width: 100%" />
            </a-form-item>
          </a-col>
        </a-row>
        <template v-if="formData.type === 6 || formData.type === 5">
          <a-row :gutter="16">
            <a-col v-if="formData.type === 6" :span="24">
              <a-form-item
                field="id"
                :label="$t('account.player.form.equipId')"
              >
                <a-input-number
                  v-model="formData.id"
                  style="width: 100%"
                  @blur="handleIdBlur"
                />
              </a-form-item>
            </a-col>

            <!-- 物品/装备 信息展示 -->
            <a-col v-if="itemInfo.name" :span="24">
              <div class="item-info-container">
                <div class="item-icon-wrapper">
                  <img :src="itemIconUrl" alt="Item Icon" class="item-icon" />
                </div>
                <div class="item-details">
                  <a-input v-model="itemInfo.name" readonly> </a-input>
                  <a-textarea
                    v-model="itemInfo.desc"
                    readonly
                    auto-size
                    style="margin-top: 8px"
                  />
                </div>
              </div>
            </a-col>

            <a-col :span="24">
              <a-form-item
                field="owner"
                :label="$t('account.player.form.owner')"
              >
                <a-input v-model="formData.owner" style="width: 100%" />
              </a-form-item>
            </a-col>
            <a-col :span="24">
              <a-form-item
                field="expireType"
                :label="$t('account.player.form.expire.type')"
              >
                <a-radio-group v-model="formData.expireType" type="button">
                  <a-radio :value="0">{{
                    $t('account.player.form.expire.permanent')
                  }}</a-radio>
                  <a-radio :value="1">{{
                    $t('account.player.form.expire.minutes')
                  }}</a-radio>
                  <a-radio :value="2">{{
                    $t('account.player.form.expire.date')
                  }}</a-radio>
                </a-radio-group>
              </a-form-item>
            </a-col>
            <a-col v-if="formData.expireType === 1" :span="24">
              <a-form-item
                field="expire"
                :label="
                  isFlaggedAsLock
                    ? $t('account.player.form.expire.lock')
                    : $t('account.player.form.expire')
                "
              >
                <a-input-number
                  v-model="formData.expire"
                  :placeholder="$t('account.player.form.expire.placeholder')"
                  style="width: 100%"
                />
              </a-form-item>
            </a-col>
            <a-col v-if="formData.expireType === 2" :span="24">
              <a-form-item
                field="expireDate"
                :label="
                  isFlaggedAsLock
                    ? $t('account.player.form.expire.lock')
                    : $t('account.player.form.expire')
                "
              >
                <a-date-picker
                  v-model="formData.expireDate"
                  show-time
                  format="YYYY-MM-DD HH:mm:ss"
                  style="width: 100%"
                />
              </a-form-item>
            </a-col>
            <a-col :span="24">
              <a-form-item field="flag" :label="$t('account.player.form.flag')">
                <a-select
                  v-model="formData.flag"
                  multiple
                  style="width: 100%"
                  :max-tag-count="3"
                >
                  <a-option :value="0x01">{{
                    $t('account.player.form.flag.lock')
                  }}</a-option>
                  <a-option :value="0x02">{{
                    $t('account.player.form.flag.spikes')
                  }}</a-option>
                  <a-option :value="0x04">{{
                    $t('account.player.form.flag.cold')
                  }}</a-option>
                  <a-option :value="0x08">{{
                    $t('account.player.form.flag.untradeable')
                  }}</a-option>
                  <a-option :value="0x10">{{
                    $t('account.player.form.flag.karma')
                  }}</a-option>
                  <a-option :value="0x80">{{
                    $t('account.player.form.flag.pet_come')
                  }}</a-option>
                  <a-option :value="0x100">{{
                    $t('account.player.form.flag.account_sharing')
                  }}</a-option>
                  <a-option :value="0x200">{{
                    $t('account.player.form.flag.merge_untradeable')
                  }}</a-option>
                </a-select>
              </a-form-item>
            </a-col>
            <template v-if="formData.type === 6">
              <a-col :span="12">
                <a-form-item field="str" :label="$t('account.player.form.str')">
                  <a-input-number v-model="formData.str" style="width: 100%" />
                </a-form-item>
              </a-col>
              <a-col :span="12">
                <a-form-item field="dex" :label="$t('account.player.form.dex')">
                  <a-input-number v-model="formData.dex" style="width: 100%" />
                </a-form-item>
              </a-col>
              <a-col :span="12">
                <a-form-item field="int" :label="$t('account.player.form.int')">
                  <a-input-number v-model="formData.int" style="width: 100%" />
                </a-form-item>
              </a-col>
              <a-col :span="12">
                <a-form-item field="luk" :label="$t('account.player.form.luk')">
                  <a-input-number v-model="formData.luk" style="width: 100%" />
                </a-form-item>
              </a-col>
              <a-col :span="12">
                <a-form-item field="hp" :label="$t('account.player.form.hp')">
                  <a-input-number v-model="formData.hp" style="width: 100%" />
                </a-form-item>
              </a-col>
              <a-col :span="12">
                <a-form-item field="mp" :label="$t('account.player.form.mp')">
                  <a-input-number v-model="formData.mp" style="width: 100%" />
                </a-form-item>
              </a-col>
              <a-col :span="12">
                <a-form-item
                  field="pAtk"
                  :label="$t('account.player.form.pAtk')"
                >
                  <a-input-number v-model="formData.pAtk" style="width: 100%" />
                </a-form-item>
              </a-col>
              <a-col :span="12">
                <a-form-item
                  field="mAtk"
                  :label="$t('account.player.form.mAtk')"
                >
                  <a-input-number v-model="formData.mAtk" style="width: 100%" />
                </a-form-item>
              </a-col>
              <a-col :span="12">
                <a-form-item
                  field="pDef"
                  :label="$t('account.player.form.pDef')"
                >
                  <a-input-number v-model="formData.pDef" style="width: 100%" />
                </a-form-item>
              </a-col>
              <a-col :span="12">
                <a-form-item
                  field="mDef"
                  :label="$t('account.player.form.mDef')"
                >
                  <a-input-number v-model="formData.mDef" style="width: 100%" />
                </a-form-item>
              </a-col>
              <a-col :span="12">
                <a-form-item field="acc" :label="$t('account.player.form.acc')">
                  <a-input-number v-model="formData.acc" style="width: 100%" />
                </a-form-item>
              </a-col>
              <a-col :span="12">
                <a-form-item
                  field="avoid"
                  :label="$t('account.player.form.avoid')"
                >
                  <a-input-number
                    v-model="formData.avoid"
                    style="width: 100%"
                  />
                </a-form-item>
              </a-col>
              <a-col :span="12">
                <a-form-item
                  field="hands"
                  :label="$t('account.player.form.hands')"
                >
                  <a-input-number
                    v-model="formData.hands"
                    style="width: 100%"
                  />
                </a-form-item>
              </a-col>
              <a-col :span="12">
                <a-form-item
                  field="speed"
                  :label="$t('account.player.form.speed')"
                >
                  <a-input-number
                    v-model="formData.speed"
                    style="width: 100%"
                  />
                </a-form-item>
              </a-col>
              <a-col :span="12">
                <a-form-item
                  field="jump"
                  :label="$t('account.player.form.jump')"
                >
                  <a-input-number v-model="formData.jump" style="width: 100%" />
                </a-form-item>
              </a-col>
              <a-col :span="12">
                <a-form-item
                  field="level"
                  :label="$t('account.player.form.level')"
                >
                  <a-input-number
                    v-model="formData.level"
                    style="width: 100%"
                  />
                </a-form-item>
              </a-col>
              <a-col :span="12">
                <a-form-item
                  field="itemLevel"
                  :label="$t('account.player.form.itemLevel')"
                >
                  <a-input-number
                    v-model="formData.itemLevel"
                    style="width: 100%"
                  />
                </a-form-item>
              </a-col>
              <a-col :span="12">
                <a-form-item
                  field="upgradeSlot"
                  :label="$t('account.player.form.upgradeSlot')"
                >
                  <a-input-number
                    v-model="formData.upgradeSlot"
                    style="width: 100%"
                  />
                </a-form-item>
              </a-col>
            </template>
          </a-row>
        </template>
      </a-form>
    </a-modal>
    <warp-modal
      v-model:visible="warpFormVisible"
      :loading="loading"
      @submit="submitWarp"
    />
    <edit-player-modal
      v-model:visible="editFormVisible"
      :player="editTarget"
      @success="loadData"
    />
  </div>
</template>

<script setup lang="ts">
  import { ref, onMounted, onUnmounted, watch, computed, reactive } from 'vue';
  import { Message } from '@arco-design/web-vue';
  import { useI18n } from 'vue-i18n';
  import useLoading from '@/hooks/loading';
  import {
    getPlayerList,
    GiveForm,
    givePlayerSrc,
    OnlinePlayer,
    getEquInitialInfo,
    getItemInitialInfo,
  } from '@/api/player';
  import { getIconUrl } from '@/utils/mapleStoryAPI';
  import WarpModal from './WarpModal.vue';
  import EditPlayerModal from './EditPlayerModal.vue';

  const { t } = useI18n();
  const { loading, setLoading } = useLoading(false);
  const tableData = ref<OnlinePlayer[]>([]);
  const total = ref(0);
  const page = ref(1);
  const size = ref(14);
  const isMobile = ref(false);

  const filterForm = ref<{
    id?: number;
    name?: string;
    map?: number;
    status: number;
  }>({
    id: undefined,
    name: undefined,
    map: undefined,
    status: 1,
  });
  const giveFormVisible = ref(false);
  const giveFormTitle = ref('');
  const warpFormVisible = ref(false);
  const warpTarget = ref<OnlinePlayer | null>(null);
  const editFormVisible = ref(false);
  const editTarget = ref<OnlinePlayer | null>(null);

  const formData = ref<GiveForm>({
    type: 5,
    expireType: 0,
  });

  const itemInfo = reactive({
    name: '',
    desc: '',
  });
  const itemIconUrl = ref('');

  const isFlaggedAsLock = computed(() => {
    return (
      Array.isArray(formData.value.flag) && formData.value.flag.includes(0x01)
    );
  });

  const checkScreen = () => {
    isMobile.value = window.innerWidth < 768;
  };

  onMounted(() => {
    checkScreen();
    window.addEventListener('resize', checkScreen);
  });

  onUnmounted(() => {
    window.removeEventListener('resize', checkScreen);
  });

  const loadData = async () => {
    setLoading(true);
    try {
      const { data } = await getPlayerList(
        page.value,
        size.value,
        filterForm.value.id,
        filterForm.value.name,
        filterForm.value.map,
        filterForm.value.status
      );
      tableData.value = data.records;
      total.value = data.totalRow;
    } finally {
      setLoading(false);
    }
  };
  loadData();

  const refreshClick = () => {
    page.value = 1;
    loadData();
  };

  const pageChange = (data: number) => {
    page.value = data;
    loadData();
  };

  const pageSizeChange = (data: number) => {
    page.value = 1;
    size.value = data;
    loadData();
  };

  const resetClick = () => {
    filterForm.value.id = undefined;
    filterForm.value.name = undefined;
    filterForm.value.map = undefined;
    filterForm.value.status = 1;
    page.value = 1;
    loadData();
  };

  const globalGiveClick = () => {
    giveFormTitle.value = '全服发放资源';
    formData.value = {
      type: 5,
      playerId: 0,
      expireType: 0,
    };
    giveFormVisible.value = true;
  };

  const giveClick = (data: OnlinePlayer) => {
    giveFormTitle.value = '发放资源';
    formData.value = {
      worldId: data.world,
      playerId: data.id,
      player: data.name,
      type: 5,
      expireType: 0,
    };
    giveFormVisible.value = true;
  };

  const editClick = (record: OnlinePlayer) => {
    editTarget.value = record;
    editFormVisible.value = true;
  };

  const submitClick = async () => {
    setLoading(true);
    try {
      const submitData = { ...formData.value };
      if (submitData.type === 6 || submitData.type === 5) {
        if (submitData.expireType === 0) {
          submitData.expire = -1;
        } else if (submitData.expireType === 2 && submitData.expireDate) {
          const now = new Date().getTime();
          const target = new Date(submitData.expireDate).getTime();
          const diffMinutes = Math.floor((target - now) / (1000 * 60));
          submitData.expire = diffMinutes > 0 ? diffMinutes : 0;
        }
        // 处理 flag
        if (Array.isArray(submitData.flag)) {
          // eslint-disable-next-line no-bitwise
          submitData.flag = submitData.flag.reduce((acc, cur) => acc | cur, 0);
        }
      }
      await givePlayerSrc(submitData);
      Message.success(t('message.success'));
    } finally {
      setLoading(false);
    }
  };

  const handleAllPlayerWarp = () => {
    warpTarget.value = null;
    warpFormVisible.value = true;
  };

  const handleGlobalAction = (
    value: string | number | Record<string, any> | undefined
  ) => {
    if (value === 'warp') {
      handleAllPlayerWarp();
    } else if (value === 'give') {
      globalGiveClick();
    }
  };

  const calculateOnlineTime = (loginTime?: string) => {
    if (!loginTime) return '-';
    const start = new Date(loginTime).getTime();
    const now = new Date().getTime();
    const diff = now - start;

    const hours = Math.floor(diff / (1000 * 60 * 60));
    const minutes = Math.floor((diff % (1000 * 60 * 60)) / (1000 * 60));

    return `${hours}h ${minutes}m`;
  };

  const handleWarp = (record: OnlinePlayer) => {
    warpTarget.value = record;
    warpFormVisible.value = true;
  };

  const submitWarp = async (mapId: number) => {
    setLoading(true);
    try {
      const data: GiveForm = {
        type: 13,
        quantity: mapId,
      };
      if (warpTarget.value) {
        data.worldId = warpTarget.value.world;
        data.playerId = warpTarget.value.id;
        data.player = warpTarget.value.name;
      } else {
        data.playerId = 0;
      }
      await givePlayerSrc(data);
      Message.success(t('message.success'));
      warpFormVisible.value = false;
      loadData();
    } finally {
      setLoading(false);
    }
  };

  watch(
    () => formData.value.expireType,
    () => {
      formData.value.expire = undefined;
      formData.value.expireDate = undefined;
    }
  );

  const handleTypeChange = () => {
    // 切换类型时重置部分数据
    formData.value.id = undefined;
    itemInfo.name = '';
    itemInfo.desc = '';
    itemIconUrl.value = '';
    // 重置装备属性
    if (formData.value.type !== 6) {
      formData.value.str = undefined;
      formData.value.dex = undefined;
      formData.value.int = undefined;
      formData.value.luk = undefined;
      formData.value.hp = undefined;
      formData.value.mp = undefined;
      formData.value.pAtk = undefined;
      formData.value.mAtk = undefined;
      formData.value.pDef = undefined;
      formData.value.mDef = undefined;
      formData.value.acc = undefined;
      formData.value.avoid = undefined;
      formData.value.hands = undefined;
      formData.value.speed = undefined;
      formData.value.jump = undefined;
      formData.value.upgradeSlot = undefined;
      formData.value.level = undefined;
      formData.value.itemLevel = undefined;
    }
  };

  const handleIdBlur = async () => {
    if (!formData.value.id) return;

    setLoading(true);
    try {
      itemInfo.name = '';
      itemInfo.desc = '';
      itemIconUrl.value = '';

      if (formData.value.type === 6) {
        // 装备
        const { data } = await getEquInitialInfo(formData.value.id);
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        const equipData = data as any;
        if (equipData) {
          itemInfo.name = equipData.name;
          itemInfo.desc = equipData.desc;
          itemIconUrl.value = getIconUrl('item', formData.value.id);

          formData.value.str = equipData.str || 0;
          formData.value.dex = equipData.dex || 0;
          formData.value.int = equipData.int || 0;
          formData.value.luk = equipData.luk || 0;
          formData.value.hp = equipData.hp || 0;
          formData.value.mp = equipData.mp || 0;
          formData.value.pAtk = equipData.pAtk || 0;
          formData.value.mAtk = equipData.mAtk || 0;
          formData.value.pDef = equipData.pDef || 0;
          formData.value.mDef = equipData.mDef || 0;
          formData.value.acc = equipData.acc || 0;
          formData.value.avoid = equipData.avoid || 0;
          formData.value.hands = equipData.hands || 0;
          formData.value.speed = equipData.speed || 0;
          formData.value.jump = equipData.jump || 0;
          formData.value.upgradeSlot = equipData.upgradeSlot || 0;
          formData.value.level = equipData.level || 0;
          formData.value.itemLevel = equipData.itemLevel || 1;
          Message.success('装备信息加载成功');
        } else {
          Message.warning('未找到该装备信息');
        }
      } else if (formData.value.type === 5) {
        // 道具
        const { data } = await getItemInitialInfo(formData.value.id);
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        const itemData = data as any;
        if (itemData) {
          itemInfo.name = itemData.name;
          itemInfo.desc = itemData.desc;
          itemIconUrl.value = getIconUrl('item', formData.value.id);
          Message.success('道具信息加载成功');
        } else {
          Message.warning('未找到该道具信息');
        }
      }
    } catch (error) {
      // Message.error('获取信息失败');
    } finally {
      setLoading(false);
    }
  };
</script>

<style scoped>
  .mobile-card {
    margin-bottom: 1rem;
    border: 1px solid var(--color-border-2);
  }
  .form-aligned :deep(.arco-form-item-label-col) {
    flex: 0 0 120px !important;
    width: 120px !important;
    display: flex;
    align-items: center;
    justify-content: flex-end;
    white-space: nowrap;
    padding-right: 12px;
  }
  .form-aligned :deep(.arco-form-item-wrapper-col) {
    flex: 1;
    width: auto;
    max-width: none;
  }
  .item-info-container {
    display: flex;
    margin-bottom: 20px;
    border: 1px solid var(--color-neutral-3);
    padding: 10px;
    border-radius: 4px;
    margin-left: 120px; /* Align with form inputs */
  }
  .item-icon-wrapper {
    margin-right: 16px;
    display: flex;
    align-items: center;
    justify-content: center;
    width: 60px;
  }
  .item-icon {
    max-width: 100%;
    max-height: 100%;
  }
  .item-details {
    flex: 1;
  }
</style>
