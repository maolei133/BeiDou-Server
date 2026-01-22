package org.gms.service;

import com.mybatisflex.core.paginate.Page;
import com.mybatisflex.core.query.QueryWrapper;
import lombok.AllArgsConstructor;
import org.gms.client.Character;
import org.gms.client.Client;
import org.gms.client.Client.CharNameAndId;
import org.gms.client.DefaultDates;
import org.gms.config.GameConfig;
import org.gms.dao.entity.*;
import org.gms.dao.mapper.*;
import org.gms.model.dto.AddAccountDTO;
import org.gms.model.dto.UpdateAccountByGmDTO;
import org.gms.model.dto.UpdateAccountByUserDTO;
import org.gms.net.server.Server;
import org.gms.util.BCrypt;
import org.gms.util.HexTool;
import org.gms.util.I18nUtil;
import org.gms.util.RequireUtil;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.sql.Timestamp;
import java.util.ArrayList;
import java.util.List;
import java.util.NoSuchElementException;
import java.util.Set;

import static org.gms.client.Client.LOGIN_LOGGEDIN;
import static org.gms.client.Client.LOGIN_NOTLOGGEDIN;
import static org.gms.dao.entity.table.AccountsDOTableDef.ACCOUNTS_D_O;
import static org.gms.dao.entity.table.CharactersDOTableDef.CHARACTERS_D_O;
import static org.gms.dao.entity.table.HwidbansDOTableDef.HWIDBANS_D_O;
import static org.gms.dao.entity.table.IpbansDOTableDef.IPBANS_D_O;
import static org.gms.dao.entity.table.MacbansDOTableDef.MACBANS_D_O;

@Service
@AllArgsConstructor
public class AccountService {
    private final AccountsMapper accountsMapper;
    private final CharactersMapper charactersMapper;
    private final IpbansMapper ipbansMapper;
    private final MacbansMapper macbansMapper;
    private final HwidbansMapper hwidbansMapper;
    private final QuickslotkeymappedMapper quickslotkeymappedMapper;
    private final VotingrecordsMapper votingrecordsMapper;

    public AccountsDO findByName(String name) {
        return accountsMapper.selectOneByName(name);
    }

    public AccountsDO findById(int id) {
        return accountsMapper.selectOneById(id);
    }

    public AccountsDO getCurrentUser() {
        UserDetails userDetails = (UserDetails) SecurityContextHolder.getContext().getAuthentication().getPrincipal();
        return findByName(userDetails.getUsername());
    }

    public Page<AccountsDO> getAccountList(Integer page,
                                           Integer size,
                                           Integer id,
                                           String name,
                                           String lastLoginStart,
                                           String lastLoginEnd,
                                           String createdAtStart,
                                           String createdAtEnd) {
        QueryWrapper queryWrapper = new QueryWrapper();
        if (id != null) queryWrapper.eq("id", id);
        if (name != null) queryWrapper.like("name", name);
        if (lastLoginStart != null) queryWrapper.ge(AccountsDO::getLastlogin, lastLoginStart);
        if (lastLoginEnd != null) queryWrapper.le(AccountsDO::getLastlogin, lastLoginEnd);
        if (createdAtStart != null) queryWrapper.ge(AccountsDO::getCreatedat, createdAtStart);
        if (createdAtEnd != null) queryWrapper.le(AccountsDO::getCreatedat, createdAtEnd);

        if (page == null) page = 1;
        if (size == null) size = Integer.MAX_VALUE;
        return accountsMapper.paginateWithRelations(page, size, queryWrapper);
    }

    public void update(AccountsDO condition) {
        accountsMapper.update(condition);
    }

    public void addAccount(AddAccountDTO submitData) throws NoSuchAlgorithmException {
        // 防止swagger调用，后续的语言路由都受影响
        RequireUtil.requireNotNull(submitData.getLanguage(), I18nUtil.getExceptionMessage("LANGUAGE_NOT_SUPPORT"));
        RequireUtil.requireNull(findByName(submitData.getName()), I18nUtil.getExceptionMessage("AccountService.addAccount.exception1"));
        AccountsDO account = AccountsDO.builder()
                .name(submitData.getName())
                .password(encryptPassword(submitData.getPassword()))
                .birthday(submitData.getBirthday())
                .tempban(Timestamp.valueOf(DefaultDates.getTempban()))
                .language(submitData.getLanguage())
                .lastlogin(Timestamp.valueOf(DefaultDates.getTempban()))
                .build();
        // 可以直接用insertSelective忽略null值
        accountsMapper.insertSelective(account);
    }

    public void updateAccountByUser(UpdateAccountByUserDTO submitData) throws NoSuchAlgorithmException {
        AccountsDO account = getCurrentUser();
        RequireUtil.requireTrue(checkPassword(submitData.getOldPwd(), account), I18nUtil.getExceptionMessage("AccountService.updateAccountByUser.oldPassword"));
        // 防止swagger调用，后续的语言路由都受影响
        RequireUtil.requireNotNull(submitData.getLanguage(), I18nUtil.getExceptionMessage("LANGUAGE_NOT_SUPPORT"));

        AccountsDO newData = new AccountsDO();
        newData.setId(account.getId());
        if (submitData.getNewPwd() != null && submitData.getNewPwd().length() >= 6) {
            newData.setPassword(encryptPassword(submitData.getNewPwd()));
        }
        newData.setPin(submitData.getPin());
        newData.setPic(submitData.getPic());
        newData.setBirthday(submitData.getBirthday());
        newData.setNick(submitData.getNick());
        newData.setEmail(submitData.getEmail());
        newData.setLanguage(submitData.getLanguage());

        accountsMapper.update(newData);
    }

    public void updateAccountByGM(int id, UpdateAccountByGmDTO submitData) throws NoSuchAlgorithmException {
        AccountsDO account = findById(id);
        RequireUtil.requireNotNull(account, I18nUtil.getExceptionMessage("AccountService.id.NotExist"));
        // 防止swagger调用，后续的语言路由都受影响
        RequireUtil.requireNotNull(account.getLanguage(), I18nUtil.getExceptionMessage("LANGUAGE_NOT_SUPPORT"));
        RequireUtil.requireFalse(account.getLoggedin() == LOGIN_LOGGEDIN, I18nUtil.getExceptionMessage("AccountService.isOnline"));
        if (submitData.getNewPwd() != null && submitData.getNewPwd().length() >= 6) {
            account.setPassword(encryptPassword(submitData.getNewPwd()));
        }
        account.setPin(submitData.getPin());
        account.setPic(submitData.getPic());
        account.setBirthday(submitData.getBirthday());
        account.setNxCredit(submitData.getNxCredit());
        account.setMaplePoint(submitData.getMaplePoint());
        account.setNxPrepaid(submitData.getNxPrepaid());
        account.setCharacterslots(submitData.getCharacterslots());
        account.setGender(submitData.getGender());
        account.setWebadmin(submitData.getWebadmin());
        account.setNick(submitData.getNick());
        account.setMute(submitData.getMute());
        account.setEmail(submitData.getEmail());
        account.setRewardpoints(submitData.getRewardpoints());
        account.setVotepoints(submitData.getVotepoints());
        account.setLanguage(submitData.getLanguage());

        accountsMapper.update(account);
    }

    public void deleteAccountByGM(int id) {
        RequireUtil.requireNotNull(findById(id), I18nUtil.getExceptionMessage("AccountService.id.NotExist"));
        accountsMapper.deleteById(id);
    }

    public String encryptPassword(String password) throws NoSuchAlgorithmException {
        return GameConfig.getServerBoolean("bcrypt_migration") ? BCrypt.hashpw(password, BCrypt.gensalt(12)) : BCrypt.hashpwSHA512(password);
    }

    public boolean checkPassword(String pwd, AccountsDO accountsDO) {
        String passHash = accountsDO.getPassword();
        if (passHash.charAt(0) == '$' && passHash.charAt(1) == '2' && BCrypt.checkpw(pwd, passHash)) {
            return true;
        } else {
            return pwd.equals(passHash) || checkHash(passHash, "SHA-1", pwd) || checkHash(passHash, "SHA-512", pwd);
        }
    }

    private static boolean checkHash(String hash, String type, String password) {
        try {
            MessageDigest digester = MessageDigest.getInstance(type);
            digester.update(password.getBytes(StandardCharsets.UTF_8), 0, password.length());
            return HexTool.toHexString(digester.digest()).replace(" ", "").toLowerCase().equals(hash);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("Encoding the string failed", e);
        }
    }

    public void resetAllLoggedIn(int id) {
        RequireUtil.requireNotNull(findById(id), I18nUtil.getExceptionMessage("AccountService.id.NotExist"));

        AccountsDO account = new AccountsDO();
        account.setId(id);
        account.setLoggedin(LOGIN_NOTLOGGEDIN);
        accountsMapper.update(account);
    }

    public void banAccount(int accountId, String reason) {
        RequireUtil.requireNotNull(findById(accountId), I18nUtil.getExceptionMessage("AccountService.id.NotExist"));

        // 封停账号
        AccountsDO account = new AccountsDO();
        account.setId(accountId);
        account.setBanned(true);
        account.setBanreason(reason);
        accountsMapper.update(account);
        // 遍历账号下的角色，如果在线，追封客户端/Mac/IP
        List<CharactersDO> characterList = charactersMapper.selectIdAndWorldListByAccountId(accountId); // 仅查询角色ID和所在world
        for (CharactersDO chr : characterList) {
            Character player = Server.getInstance()
                    .getWorlds()
                    .get(chr.getWorld())
                    .getPlayerStorage()
                    .getCharacterById(chr.getId());
            if (player == null) return; // 角色离线
            player.setBanned(true);
            Client c = player.getClient(); // 角色在线，获取客户端
            c.banMacs(); // 封禁Mac
            // c.banHWID(); // 封禁客户端 操作不可逆？
            // 封禁IP
            String ip = c.getRemoteAddress();
            banIp(ip, accountId);
            // 强制离线，这个方法只是中断了连接不会造成客户端退出，但是实际跟掉线没什么区别
            c.disconnect(false, false);
        }
    }

    public void unbanAccount(int accountId) {
        unbanAccount(accountId, false, false, false, null, null);
    }

    public void unbanAccount(int accountId, boolean unbanIp, boolean unbanMac, boolean unbanHwid, List<String> ips, List<String> macs) {
        RequireUtil.requireNotNull(findById(accountId), I18nUtil.getExceptionMessage("AccountService.id.NotExist"));

        // 解封账号
        AccountsDO account = new AccountsDO();
        account.setId(accountId);
        account.setBanned(false);
        account.setTempban(Timestamp.valueOf(DefaultDates.getTempban())); // Reset tempban
        accountsMapper.update(account);
        
        String aidStr = String.valueOf(accountId);

        // 解封Mac
        if (unbanMac) {
            // 1. 如果提供了具体的 MAC 列表，则只删除这些 MAC
            if (macs != null && !macs.isEmpty()) {
                for (String mac : macs) {
                    if (mac != null && !mac.trim().isEmpty()) {
                        macbansMapper.deleteByQuery(QueryWrapper.create().where(MACBANS_D_O.MAC.eq(mac.trim())));
                    }
                }
            } else {
                // 2. 如果没有提供列表（兼容旧逻辑），则删除该账号关联的所有 MAC
                macbansMapper.deleteByQuery(QueryWrapper.create().where(MACBANS_D_O.AID.eq(aidStr)));
            }
        }
        
        // 解封Ip
        if (unbanIp) {
            // 1. 如果提供了具体的 IP 列表，则只删除这些 IP
            if (ips != null && !ips.isEmpty()) {
                for (String ip : ips) {
                    if (ip != null && !ip.trim().isEmpty()) {
                        ipbansMapper.deleteByQuery(QueryWrapper.create().where(IPBANS_D_O.IP.eq(ip.trim())));
                    }
                }
            } else {
                // 2. 如果没有提供列表（兼容旧逻辑），则删除该账号关联的所有 IP
                ipbansMapper.deleteByQuery(QueryWrapper.create().where(IPBANS_D_O.AID.eq(aidStr)));
            }
        }

        // 解封Hwid
        if (unbanHwid) {
            AccountsDO acc = accountsMapper.selectOneById(accountId);
            if (acc != null && acc.getHwid() != null) {
                hwidbansMapper.deleteByQuery(QueryWrapper.create().where(HWIDBANS_D_O.HWID.eq(acc.getHwid())));
            }
        }
    }

    public void resetAllLoggedIn() {
        accountsMapper.updateAllLoggedIn(0);
    }

    public void ban(Character chr, String reason) {
        accountsMapper.update(AccountsDO.builder().banned(true).id(chr.getAccountId()).banreason(reason).build());
        // 更新在线的ban状态
        chr.setBanned(true);
    }

    public void ban(String str, String reason, boolean isAccount) {
        if (str.matches("[0-9]{1,3}\\..*")) {
            if (isBanned(str)) {
                return;
            }
            ipbansMapper.insertSelective(IpbansDO.builder().ip(str).build());
            return;
        }
        Integer accountId = null;
        if (isAccount) {
            AccountsDO accountsDO = findByName(str);
            if (accountsDO != null) {
                accountId = accountsDO.getId();
            }
        } else {
            List<CharactersDO> charactersDOS = charactersMapper.selectListByQuery(QueryWrapper.create().where(CHARACTERS_D_O.NAME.eq(str)));
            if (!charactersDOS.isEmpty()) {
                accountId = charactersDOS.getFirst().getAccountid();
            }
        }
        if (accountId == null) {
            throw new NoSuchElementException();
        }
        accountsMapper.update(AccountsDO.builder()
                .id(accountId)
                .banreason(reason)
                .banned(true)
                .build());
    }

    public boolean isBanned(String ip) {
        return ipbansMapper.selectCountByQuery(QueryWrapper.create().where(IPBANS_D_O.IP.eq(ip))) > 0;
    }

    public QuickslotkeymappedDO getQuickSlotKeyMap(int accountId) {
        return quickslotkeymappedMapper.selectOneById(accountId);
    }

    public List<Integer> getAllAccountIds() {
        return accountsMapper.selectListByQuery(QueryWrapper.create().select(ACCOUNTS_D_O.ID)).stream().map(AccountsDO::getId).toList();
    }

    public boolean hasBannedIP(String remoteAddress) {
        return ipbansMapper.selectCountByQuery(QueryWrapper.create().where(IPBANS_D_O.IP.like(remoteAddress))) > 0;
    }

    public boolean hasBannedHWID(String hwid) {
        return hwidbansMapper.selectCountByQuery(QueryWrapper.create().where(HWIDBANS_D_O.HWID.like(hwid))) > 0;
    }

    public boolean hasBannedMac(Set<String> macs) {
        if (macs.isEmpty()) {
            return false;
        }
        return macbansMapper.selectCountByQuery(QueryWrapper.create().where(MACBANS_D_O.MAC.in(macs))) > 0;
    }

    public List<CharNameAndId> loadCharactersInternal(int accountId, int worldId) {
        List<CharactersDO> charsDO = charactersMapper.selectListByQuery(
                QueryWrapper.create().where(CHARACTERS_D_O.ACCOUNTID.eq(accountId)).and(CHARACTERS_D_O.WORLD.eq(worldId)));
        List<CharNameAndId> chars = new ArrayList<>();
        for (CharactersDO c : charsDO) {
            chars.add(new CharNameAndId(c.getName(), c.getId()));
        }
        return chars;
    }

    public int getVoteTime(String accountName) {
        VotingrecordsDO record = votingrecordsMapper.selectOneByQuery(
                QueryWrapper.create().where("UPPER(account) = UPPER(?)", accountName));
        if (record != null) {
            return record.getDate();
        }
        return -1;
    }

    public String loadHwid(int accountId) {
        AccountsDO account = accountsMapper.selectOneById(accountId);
        return account != null ? account.getHwid() : null;
    }

    public String loadMacs(int accountId) {
        AccountsDO account = accountsMapper.selectOneById(accountId);
        return account != null ? account.getMacs() : null;
    }

    public void banHwid(String hwid) {
        if (hwidbansMapper.selectCountByQuery(QueryWrapper.create().where(HWIDBANS_D_O.HWID.eq(hwid))) == 0) {
            hwidbansMapper.insert(HwidbansDO.builder().hwid(hwid).build());
        }
    }

    public void banIp(String ip, int accountId) {
        if (ipbansMapper.selectCountByQuery(QueryWrapper.create().where(IPBANS_D_O.IP.eq(ip))) == 0) {
            ipbansMapper.insert(IpbansDO.builder().ip(ip).aid(String.valueOf(accountId)).build());
        }
    }

    public void banMacs(Set<String> macs, int accountId) {
        for (String mac : macs) {
            if (macbansMapper.selectCountByQuery(QueryWrapper.create().where(MACBANS_D_O.MAC.eq(mac))) == 0) {
                macbansMapper.insert(MacbansDO.builder().mac(mac).aid(String.valueOf(accountId)).build());
            }
        }
    }

    public int getActiveRecordCount(String searchValue) {
        String searchPattern = "%" + searchValue + "%";
        return (int) accountsMapper.selectCountByQuery(QueryWrapper.create()
                .where(ACCOUNTS_D_O.LOGGEDIN.gt(0))
                .and(ACCOUNTS_D_O.IP.like(searchPattern)
                        .or(ACCOUNTS_D_O.MACS.like(searchPattern))
                        .or(ACCOUNTS_D_O.HWID.like(searchPattern))));
    }

    public int getTodayLoginCount(String searchValue) {
        String searchPattern = "%" + searchValue + "%";
        return (int) accountsMapper.selectCountByQuery(QueryWrapper.create()
                .where(ACCOUNTS_D_O.LOGGEDIN.gt(0))
                .and(ACCOUNTS_D_O.IP.like(searchPattern)
                        .or(ACCOUNTS_D_O.MACS.like(searchPattern))
                        .or(ACCOUNTS_D_O.HWID.like(searchPattern)))
                .and(ACCOUNTS_D_O.LASTLOGIN.isNotNull())
                .and("DATE(lastlogin) = CURDATE()"));
    }

    public void setPin(int accountId, String pin) {
        accountsMapper.update(AccountsDO.builder().id(accountId).pin(pin).build());
    }

    public void setPic(int accountId, String pic) {
        accountsMapper.update(AccountsDO.builder().id(accountId).pic(pic).build());
    }

    public AccountsDO getLoginState(int accountId) {
        return accountsMapper.selectOneById(accountId);
    }

    public void updateLoginState(int accountId, int newState) {
        accountsMapper.update(AccountsDO.builder()
                .id(accountId)
                .loggedin(newState)
                .lastlogin(new Timestamp(System.currentTimeMillis()))
                .build());
    }

    public void updateHwid(int accountId, String hwid) {
        accountsMapper.update(AccountsDO.builder().id(accountId).hwid(hwid).build());
    }

    public void updateMacs(int accountId, String macs) {
        accountsMapper.update(AccountsDO.builder().id(accountId).macs(macs).build());
    }

    public void updateIps(int accountId, String ips) {
        accountsMapper.update(AccountsDO.builder().id(accountId).ip(ips).build());
    }

    public boolean acceptToS(int accountId) {
        AccountsDO account = accountsMapper.selectOneById(accountId);
        if (account != null && Boolean.TRUE.equals(account.getTos())) {
            return true;
        }
        accountsMapper.update(AccountsDO.builder().id(accountId).tos(true).build());
        return false;
    }

    public int getVotePoints(int accountId) {
        AccountsDO account = accountsMapper.selectOneById(accountId);
        return account != null ? account.getVotepoints() : 0;
    }

    public void saveVotePoints(int accountId, int points) {
        accountsMapper.update(AccountsDO.builder().id(accountId).votepoints(points).build());
    }

    public boolean gainCharacterSlot(int accountId, int currentSlots) {
        if (currentSlots < 15) {
            accountsMapper.update(AccountsDO.builder().id(accountId).characterslots(currentSlots + 1).build());
            return true;
        }
        return false;
    }

    public byte getGReason(int accountId) {
        AccountsDO account = accountsMapper.selectOneById(accountId);
        return account != null ? account.getGreason().byteValue() : 0;
    }

    public void setGender(int accountId, byte gender) {
        accountsMapper.update(AccountsDO.builder().id(accountId).gender((int) gender).build());
    }
}
