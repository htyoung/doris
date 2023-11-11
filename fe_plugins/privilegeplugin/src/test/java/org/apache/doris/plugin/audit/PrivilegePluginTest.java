package org.apache.doris.plugin.audit;

import org.apache.doris.plugin.AuditEvent;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.junit.Test;

import java.io.IOException;

public class PrivilegePluginTest {
    private static final Logger LOG = LogManager.getLogger(PrivilegePluginTest.class);

    @Test
    public void testCreateTablePattern() {
        String[] result1 = PrivilegePlugin.getFullTableNameWithRegex("create table abc.test(");
        assert result1[0].equals("abc") && result1[1].equals("test");
        String[] result2 = PrivilegePlugin.getFullTableNameWithRegex("create table abc.test( ");
        assert result2[0].equals("abc") && result2[1].equals("test");
        String[] result3 = PrivilegePlugin.getFullTableNameWithRegex("create table abc.test ( ");
        assert result3[0].equals("abc") && result3[1].equals("test");
        String[] result4 = PrivilegePlugin.getFullTableNameWithRegex("  create   table   abc.test   (   ");
        assert result4[0].equals("abc") && result4[1].equals("test");
        String[] result5 = PrivilegePlugin.getFullTableNameWithRegex("  create   table   `abc`.`test`   (   ");
        assert result5[0].equals("abc") && result5[1].equals("test");
        String[] result6 = PrivilegePlugin.getFullTableNameWithRegex("  create   table   `test`   (   ");
        assert result6[0].isEmpty() && result6[1].equals("test");
        //大小写混合case
        String[] result7 = PrivilegePlugin.getFullTableNameWithRegex("CREATE TABLE ABC.TEST(");
        assert result7[0].equals("ABC") && result7[1].equals("TEST");
        String[] result8 = PrivilegePlugin.getFullTableNameWithRegex("create table abc.TEST( ");
        assert result8[0].equals("abc") && result8[1].equals("TEST");
        String[] result9 = PrivilegePlugin.getFullTableNameWithRegex("CREATE table ABC.test ( ");
        assert result9[0].equals("ABC") && result9[1].equals("test");
        String[] result10 = PrivilegePlugin.getFullTableNameWithRegex("  create   TABLE   abc.test   (   ");
        assert result10[0].equals("abc") && result10[1].equals("test");
        String[] result11 = PrivilegePlugin.getFullTableNameWithRegex("  create   table   `ABC`.`test`   (   ");
        assert result11[0].equals("ABC") && result11[1].equals("test");
        String[] result12 = PrivilegePlugin.getFullTableNameWithRegex("  create   table   `TEST`   (   ");
        assert result12[0].isEmpty() && result12[1].equals("TEST");
        //换行case
        String[] result13 = PrivilegePlugin.getFullTableNameWithRegex("CREATE \n" + "        TABLE ABC.TEST(");
        assert result13[0].equals("ABC") && result13[1].equals("TEST");
        String[] result14 = PrivilegePlugin.getFullTableNameWithRegex("\ncreate table abc.TEST( ");
        assert result14[0].equals("abc") && result14[1].equals("TEST");
        String[] result15 = PrivilegePlugin.getFullTableNameWithRegex("\n\nCREATE table\n" + " ABC.test ( ");
        assert result15[0].equals("ABC") && result15[1].equals("test");
        String[] result16 = PrivilegePlugin.getFullTableNameWithRegex("  create   TABLE   abc.\n" + "test   (   ");
        assert result16[0].isEmpty() && result16[1].isEmpty();
        String[] result17 = PrivilegePlugin.getFullTableNameWithRegex("  create   table   `ABC`.\n" + "`test`   (   ");
        assert result17[0].isEmpty() && result17[1].isEmpty();
        String[] result18 = PrivilegePlugin.getFullTableNameWithRegex("  create   table   `TEST`   (\n" + "\tcol1");
        assert result18[0].isEmpty() && result18[1].equals("TEST");
        //支持default_cluster:
        String[] result19 = PrivilegePlugin.getFullTableNameWithRegex(
                "  create   table   `default_cluster:abc`.`test`   (\n" + "\tcol1");
        assert result19[0].equals("abc") && result19[1].equals("test");
    }

    @Test
    public void testParseCreateStmt() {
        try (PrivilegePlugin privilegePlugin = new PrivilegePlugin()) {
            AuditEvent auditEvent = new AuditEvent();
            auditEvent.stmt
                    = "insert into apm_measure_detail_realtime (dt,`time`,device_source,app_version,device_brand,device_model,os_version,class_name,type,measure,env_tag,network,wakeUpSrc,isColdStart,device_id,path,page_type) values (20231123,'2023-11-23 10:44:00','jd_app_android', '2.3.88(0)','Xiaomi','2112123AC', '13','VehicleTopBarFragment','pageLoadTime', '{\"cnt\":1,\"pageLoadTime\":735}','',null, null,null,'ffffffffd68c575c000000001d274b95',null,'Fragment') , (20231123,'2023-11-23 10:44:00','jd_app_android', '2.3.88(0)','Xiaomi','2112123AC', '13','SceneCardFragment','pageLoadTime', '{\"cnt\":1,\"pageLoadTime\":567}','',null, null,null,'ffffffffd68c575c000000001d274b95',null,'Fragment') , (20231123,'2023-11-23 10:44:00','jd_app_android', '2.3.88(0)','Xiaomi','2112123AC', '13','MainActivity','pageLoadTime', '{\"cnt\":1,\"pageLoa";
            auditEvent.state = "OK";
            auditEvent.isQuery = false;
            auditEvent.user = "jd_qa_apm";
            auditEvent.db = "jd_qa_apm_test";
            privilegePlugin.parseCreateStmt(auditEvent);
        } catch (IOException e) {
            LOG.error(e);
        }
    }
}
