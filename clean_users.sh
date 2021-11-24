delete from LegacySite_card where user_id in (select user_id from LegacySite_user where username like "%dummy%");
delete from LegacySite_user where username like "%dummy%";
