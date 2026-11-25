static const char *load_fixture_op="9876543210abcdef9876543210abcdef";

static void load_fixture_reset(void) {
    g_remove(keypath);
    g_clear_pointer(&fixture_load_op,g_free);g_clear_pointer(&fixture_load_state,g_free);g_clear_pointer(&fixture_load_snapshot,g_free);
    fixture_load_finished=FALSE;fixture_drop_action=NULL;fixture_reject_action=NULL;
    listed_custom="custom:Work";returned_custom=listed_custom;
    g_autoptr(GError) error=NULL;
    check(linux_custom_publish_v18(NULL,"Work","wireguard,legacy-old",LINUX_CUSTOM_SAVE,&error),"original profile preparation");
    check(linux_custom_publish_v18(NULL,"Other","tls",LINUX_CUSTOM_SAVE,&error),"original selected profile preparation");
}

static void load_fixture_prepare(gboolean prepare_controller,gboolean stage) {
    g_auto(LinuxLoadFile) file={.directory=-1};g_autoptr(GError) error=NULL;
    check(linux_load_open(&file,FALSE,&error),"open original settings");
    g_autoptr(JsonObject) req=json_object_new();json_object_set_string_member(req,"operation_id",load_fixture_op);
    json_object_set_string_member(req,"expected_selected_node_id","exit");json_object_set_string_member(req,"id","saved");
    json_object_set_string_member(req,"expected_mode",listed_custom);g_autofree char *revision=g_strdup_printf("%u",fixture_load_revision);
    json_object_set_string_member(req,"expected_revision",revision);
    JsonObject *tokens=json_object_new();json_object_set_string_member(tokens,"exit",FIXTURE_LOAD_SHA);
    json_object_set_object_member(req,"expected_profile_tokens",tokens);
    g_autofree char *body=linux_ordered_json_v1(req);
    g_key_file_set_string(file.key,LINUX_LOAD_GROUP,"request",body);
    g_key_file_set_string(file.key,LINUX_LOAD_GROUP,"operation_id",load_fixture_op);
    g_key_file_set_string(file.key,LINUX_LOAD_GROUP,"phase","preparing_sent");
    check(linux_load_write(&file,&error),"reserve local Load");
    if(!prepare_controller)return;
    g_autoptr(JsonNode) response=linux_load_call("prepare",req,&error);check(response!=NULL,"could not prepare profile Load");
    if(!stage)return;
    JsonObject *r=json_node_get_object(response),*tx=linux_load_receipt(response,req,FALSE,&error);
    check(tx!=NULL,"prepared receipt invalid");
    check(linux_load_stage(&file,tx,req,linux_ordered_object_v1(r,"snapshot"),&error),"could not stage captured profile");
}

static void load_fixture_check(gboolean original) {
    g_auto(LinuxLoadFile) file={.directory=-1};
    check(linux_load_open(&file,FALSE,NULL),"left recovery intent after settlement");
    g_autofree char *mode=g_key_file_get_string(file.key,"state","selected_mode",NULL);
    g_autofree char *work=g_key_file_get_string(file.key,"preset:Work","layers",NULL);
    g_autofree char *other=g_key_file_get_string(file.key,"preset:Other","layers",NULL);
    check(!g_strcmp0(mode,original?"custom:Other":"custom:Work")&&!g_strcmp0(work,original?"wireguard,legacy-old":"reality,legacy-layer")&&
          !g_strcmp0(other,"tls"),"recovery changed the original selected mode, named layers or another preset");
}

static void load_recovery_faults(void) {
    const guint first=checks;
    load_fixture_reset();check(!g_chmod(keypath,0644),"prepare legacy non-private settings mode");
    g_autoptr(GError) legacy_error=NULL;
    check(linux_custom_publish_v18(NULL,"Private","wireguard",LINUX_CUSTOM_SAVE,&legacy_error),"legacy settings did not regain private permissions");
    struct stat strict;check(!g_stat(keypath,&strict)&&!(strict.st_mode&077),"legacy settings permissions leaked private profile choices");
    load_fixture_reset();load_fixture_prepare(TRUE,FALSE);
    {
        g_autoptr(GError) failure=NULL;g_auto(LinuxLoadFile) f={.directory=-1};check(linux_load_open(&f,TRUE,&failure),"open empty ordered path fixture");
        g_autoptr(JsonNode) bad=parse_json(fixture_load_snapshot);
        g_autofree char *saved_request=g_key_file_get_string(f.key,LINUX_LOAD_GROUP,"request",NULL);
        g_autoptr(JsonNode) request=parse_json(saved_request);
        json_object_set_array_member(json_node_get_object(bad),"multihop_nodes",json_array_new());
        check(!linux_load_stage(&f,json_node_get_object(request),json_node_get_object(request),json_node_get_object(bad),&failure),"empty ordered path became a plain profile");
    }
    check(linux_load_recover(load_fixture_op,NULL,NULL),"empty ordered fixture rollback");load_fixture_check(TRUE);
    for(guint boundary=0;boundary<3;boundary++){
        load_fixture_reset();load_fixture_prepare(boundary>=1,boundary>=2);
        check(linux_load_fences_launch("/api/strategy/custom")&&!linux_load_fences_launch("/api/disconnect")&&
                !linux_load_fences_launch("/api/emergency-stop"),"pending Load admitted a connection or fenced Stop");
        g_autoptr(GError) error=NULL;check(!linux_custom_publish_v18(NULL,"Other","newer",LINUX_CUSTOM_SAVE,&error),"pending Load admitted preset writes");
        g_clear_error(&error);
        check(linux_load_recover(load_fixture_op,NULL,&error),"restart failed to abort the original prepared owner");
        check(fixture_load_finished&&!strcmp(fixture_load_state,"aborted"),"aborted original owner was not finished");load_fixture_check(TRUE);
    }
    for(guint owner=0;owner<2;owner++){
        load_fixture_reset();load_fixture_prepare(FALSE,FALSE);
        g_autoptr(GKeyFile) initial=linux_unified_load_keyfile_v8();
        g_autofree char *request=g_key_file_get_string(initial,LINUX_LOAD_GROUP,"request",NULL);
        if(owner)fixture_load_revision++;
        g_autoptr(GError) failure=NULL;
        check(linux_load_recover(load_fixture_op,NULL,&failure),"absent sent request could not cancel at its original revision");
        Buffer late={0};char *reason=NULL;
        check(!fixture_load_http("/api/connection-profile/setup/load/prepare",request,&late,&reason),"late prepare published after cancellation or supersession");
        g_free(reason);load_fixture_check(TRUE);
    }
    for(guint after=0;after<2;after++){
        load_fixture_reset();load_fixture_prepare(TRUE,TRUE);fixture_fail_phase="phase=rolled_back";fixture_fail_after=after;
        g_autoptr(GError) failure=NULL;check(!linux_load_recover(load_fixture_op,NULL,&failure),"failed rollback write released original owner");
        check(!strcmp(fixture_load_state,"prepared")&&!fixture_load_finished&&linux_load_pending(),"backend released before local rollback durability");
        g_clear_error(&failure);check(linux_load_recover(load_fixture_op,NULL,&failure),"retry after rollback write failure");
        load_fixture_check(TRUE);
    }
    load_fixture_reset();
    {g_auto(LinuxLoadFile) stale={.directory=-1};g_autoptr(GError) e=NULL;
     check(linux_load_open(&stale,FALSE,&e),"capture original file identity");
     g_autoptr(GKeyFile) newer=linux_unified_load_keyfile_v8();
     g_key_file_set_string(newer,"state","selected_mode","custom:External");linux_unified_save_keyfile_v8(newer);
     g_key_file_set_string(stale.key,"state","selected_mode","custom:Work");
     check(!linux_load_write(&stale,&e),"stale file handle replaced a newer write");
     g_autofree char *mode=linux_unified_selected_mode_v8();check(!strcmp(mode,"custom:External"),"stale write erased the new owner");}
    load_fixture_reset();load_fixture_prepare(TRUE,TRUE);
    struct stat st;check(g_stat(keypath,&st)==0&&!(st.st_mode&077),"profile journal is publicly readable");
    g_autoptr(GError) error=NULL;
    {g_auto(LinuxLoadFile) lock={.directory=-1};check(linux_load_open(&lock,TRUE,&error),"capture private writer");
     check(!linux_load_recover(load_fixture_op,NULL,&error),"second recovery writer acquired the active owner");g_clear_error(&error);}
    check(!linux_load_recover("11111111111111111111111111111111",NULL,&error),"stale local request recovered another owner");g_clear_error(&error);
    g_autoptr(GKeyFile) changed=linux_unified_load_keyfile_v8();g_key_file_set_string(changed,"state","selected_mode","custom:Newer");
    linux_unified_save_keyfile_v8(changed);
    check(!linux_load_recover(load_fixture_op,NULL,&error),"rollback overwrote an externally replaced selection");g_clear_error(&error);
    check(!strcmp(fixture_load_state,"prepared")&&linux_load_pending(),"conflicting rollback released admission");
    g_autofree char *protected=linux_unified_selected_mode_v8();check(!strcmp(protected,"custom:Newer"),"recovery erased newer choice");
    g_clear_pointer(&fixture_load_op,g_free);
    check(!linux_load_recover(load_fixture_op,NULL,&error)&&linux_load_pending(),"staged absent receipt allowed rollback");g_clear_error(&error);
    load_fixture_reset();load_fixture_prepare(TRUE,TRUE);
    g_free(fixture_load_state);fixture_load_state=g_strdup("committed");fixture_drop_action="finish";
    check(!linux_load_recover(load_fixture_op,NULL,&error)&&fixture_load_finished,"lost finish did not retain its local terminal receipt");g_clear_error(&error);
    g_clear_pointer(&fixture_load_op,g_free);fixture_bad_absent=TRUE;
    check(!linux_load_recover(load_fixture_op,NULL,&error)&&linux_load_pending(),"malformed absent response cleared the terminal owner");g_clear_error(&error);
    check(linux_load_recover(load_fixture_op,NULL,&error),"finished terminal receipt could not clean its own intent");load_fixture_check(FALSE);
    load_fixture_reset();load_fixture_prepare(TRUE,TRUE);
    fixture_drop_action="abort";check(!linux_load_recover(load_fixture_op,NULL,&error),"lost abort did not preserve local recovery");
    g_clear_error(&error);check(linux_load_pending()&&!strcmp(fixture_load_state,"aborted"),"lost abort released local admission");
    check(linux_load_recover(load_fixture_op,NULL,&error),"lost abort could not be resumed");load_fixture_check(TRUE);
    load_fixture_reset();load_fixture_prepare(TRUE,TRUE);
    {g_auto(LinuxLoadFile) f={.directory=-1};check(linux_load_open(&f,TRUE,&error),"open unrelated change");
     g_key_file_set_string(f.key,"preset:Other","unrelated","untouched");check(linux_load_write(&f,&error),"persist unrelated change");}
    check(linux_load_recover(load_fixture_op,NULL,&error),"unrelated preference prevented exact rollback");
    g_autoptr(GKeyFile) keep=linux_unified_load_keyfile_v8();g_autofree char *unrelated=g_key_file_get_string(keep,"preset:Other","unrelated",NULL);
    check(!g_strcmp0(unrelated,"untouched"),"rollback changed unrelated preference");load_fixture_check(TRUE);
    load_fixture_reset();g_remove(keypath);listed_custom=NULL;returned_custom=NULL;custom_load_posts=0;
    printf("GTK profile Load durable stage/restart, late prepare, abort/finish, CAS and ownership: %u checks PASS.\n",checks-first);
}

static void load_dialog_faults(LinuxUnifiedV8 *state) {
    const guint first=checks;
    for(guint test=0;test<7;test++){
        load_fixture_reset();linux_unified_refresh_mode_combo_v8(state);fixture_fail_after=FALSE;
        switch(test){
        case 0:fixture_drop_action="prepare";break;
        case 1:fixture_fail_phase="phase=staged";break;
        case 2:fixture_fail_phase="phase=staged";fixture_fail_after=TRUE;break;
        case 3:fixture_reject_action="commit";break;
        case 4:fixture_drop_action="commit";break;
        case 5:fixture_fail_phase="phase=complete";break;
        case 6:fixture_drop_action="finish";break;
        }
        guint step=0;g_idle_add(custom_profile_response,&step);linux_profile_manager_v11(NULL,state);
        gboolean old=test<4;
        check(step==2 && fixture_load_finished && !g_strcmp0(fixture_load_state,old?"aborted":"committed"),"GTK dialog settled the wrong transaction");
        load_fixture_check(old);
        if(!old)check(!g_strcmp0(gtk_combo_box_get_active_id(GTK_COMBO_BOX(state->mode)),"custom:Work"),"lost terminal response failed to publish the confirmed view");
    }
    load_fixture_reset();g_remove(keypath);listed_custom=NULL;returned_custom=NULL;custom_load_posts=0;
    linux_unified_refresh_mode_combo_v8(state);
    printf("GTK profile Load dialog disk faults and lost prepare/commit/finish replies: %u checks PASS.\n",checks-first);
}
