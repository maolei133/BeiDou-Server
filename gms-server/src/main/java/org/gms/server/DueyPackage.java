/*
	This file is part of the OdinMS Maple Story Server
    Copyright (C) 2008 Patrick Huy <patrick.huy@frz.cc>
		       Matthias Butz <matze@odinms.de>
		       Jan Christian Meyer <vimes@odinms.de>

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU Affero General Public License as
    published by the Free Software Foundation version 3 as published by
    the Free Software Foundation. You may not use, modify or distribute
    this program under any other version of the GNU Affero General Public
    License.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Affero General Public License for more details.

    You should have received a copy of the GNU Affero General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/
package org.gms.server;

import org.gms.client.inventory.Item;

import java.sql.Timestamp;
import java.util.Calendar;

import static java.util.concurrent.TimeUnit.*;

public class DueyPackage {
    private String sender = null;
    private Item item = null;
    private int mesos = 0;
    private String message = null;
    private Calendar timestamp;
    private int packageId = 0;
    private Integer receiverId;
    private long expireTime = 0;
    private boolean quick = false;
    private long deliveryTime = 0;

    public DueyPackage(int pId, Item item) {
        this.item = item;
        packageId = pId;
    }

    public DueyPackage(int pId) { // Meso only package.
        this.packageId = pId;
    }

    public String getSender() {
        return sender;
    }

    public void setSender(String name) {
        sender = name;
    }

    public Item getItem() {
        return item;
    }

    public int getMesos() {
        return mesos;
    }

    public void setMesos(int set) {
        mesos = set;
    }

    public String getMessage() {
        return message;
    }

    public void setMessage(String m) {
        message = m;
    }

    public int getPackageId() {
        return packageId;
    }

    public Integer getReceiverId() {
        return receiverId;
    }

    public void setReceiverId(Integer receiverId) {
        this.receiverId = receiverId;
    }
    
    public boolean isQuick() {
        return quick;
    }

    public void setQuick(boolean quick) {
        this.quick = quick;
    }

    public long sentTimeInMilliseconds() {
        long time;
        if (expireTime > 0) {
            time = expireTime;
        } else {
            Calendar ts = timestamp;
            if (ts != null) {
                Calendar cal = Calendar.getInstance();
                cal.setTime(ts.getTime());
                cal.add(Calendar.MONTH, 1);  // duey representation is in an array of months.
                time = cal.getTimeInMillis();
            } else {
                return 0;
            }
        }

        long limit = System.currentTimeMillis() + DAYS.toMillis(29) + HOURS.toMillis(23);
        if (time > limit) {
            return limit;
        }
        return time;
    }

    public long getDeliveryTime() {
        return deliveryTime;
    }
    
    public void setDeliveryTime(long deliveryTime) {
        this.deliveryTime = deliveryTime;
    }
    
    public long getExpireTime() {
        return expireTime;
    }

    public void setExpireTime(long expireTime) {
        this.expireTime = expireTime;
    }

    public boolean isDeliveringTime() {
        Calendar ts = timestamp;
        if (ts != null) {
            return ts.getTimeInMillis() >= System.currentTimeMillis();
        } else {
            return false;
        }
    }

    public void setSentTime(Timestamp ts, boolean quick) {
        Calendar cal = Calendar.getInstance();
        cal.setTimeInMillis(ts.getTime());

        if (quick) {
            if (System.currentTimeMillis() - ts.getTime() < DAYS.toMillis(1)) {  // thanks inhyuk for noticing quick delivery packages unavailable to retrieve from the get-go
                cal.add(Calendar.DATE, -1);
            }
        }

        this.timestamp = cal;
    }
}
