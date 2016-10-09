<?php

/*define('MODX_API_MODE', true);
require_once dirname(dirname(__FILE__)) . '/index.php';

$modx->getService('error','error.modError');
$modx->setLogLevel(modX::LOG_LEVEL_ERROR);
$modx->setLogTarget('FILE');*/

$NAME = 'manager';
$groupName = $NAME;                     // Название группы пользователей
$mediaSourceName = $NAME;               // Название медиа источника
$roleAuthority = 9;                     // Ранг роли
$mediaSourcePath = 'assets/uploads/';   // Путь для медиа источника, если указать пустую строку медиа источник создаваться не будет
$bindMediaSourceTv = true;              // Привязывать ли источник файлов ко всем tv. Предыдущие источники будут отвязаны
$contextKey = 'web';
$users = array(
    $NAME => array(
        'username' => $NAME,
        'password' => $NAME,            // min 6 символов
        'email' => '',
    ),
);

$accessPolicy = array(
    'access_permissions' => 0, //Страницы и действия, связанные с правами доступа.
    'dashboards' => 0, //Просмотр и управление панелями.
    'element_tree' => 0, //Возможность просмотра дерева элементов в левой навигационной панели.
    'menu_reports' => 0, //Показывать в верхнем меню пункт «Отчёты».
    'menu_security' => 0, //Показывать в верхнем меню пункт «Безопасность».
    'menu_site' => 0, //Показывать в верхнем меню пункт «Сайт».
    'menu_system' => 0, //Показывать в верхнем меню пункт «Система».
    'menu_tools' => 0, //Показывать в верхнем меню пункт «Инструменты».
    'new_static_resource' => 0, //Создавать новые статичные ресурсы.
    'packages' => 0, //Использовать пакеты в системе управления пакетами.
    'remove_locks' => 0, //Удалять все блокировки на сайте.
    'settings' => 0, //Смотреть и редактировать системные настройки.
    'sources' => 0, //Управлять источниками файлов и типами источников файлов.
);




//Создаем новый шаблон политики доступа на основании админавского
$modx->lexicon->load('policy');
$modx->setLogLevel(modX::LOG_LEVEL_ERROR);

if ($templatePolicy = $modx->getObject('modAccessPolicyTemplate', array('name' => $NAME))) {
    $templatePolicyId = $templatePolicy->id;
} else {
    $response = $modx->runProcessor('security/access/policy/template/duplicate', array(
        'id' => 1, // Administrator template id
    ));

    if ($response->isError()) {
        return $modx->log(modX::LOG_LEVEL_ERROR, $response->getMessage());
    }

    $templatePolicyId = $response->getObject()['id'];

    $response = $modx->runProcessor('security/access/policy/template/update', array(
        'id' => $templatePolicyId,
        'name' => $NAME,
    ));

    if ($response->isError()) {
        return $modx->log(modX::LOG_LEVEL_ERROR, $response->getMessage());
    }
}

//Создаем политику доступа
if (!$policy = $modx->getObject('modAccessPolicy', array('name' => $NAME))) {
    $response = $modx->runProcessor('security/access/policy/create', array(
        'name' => $NAME,
        'template' => $templatePolicyId,
    ));
    if ($response->isError()) {
        return $modx->log(modX::LOG_LEVEL_ERROR, $response->getMessage());
    }
    $policyId = $response->getObject()['id'];

    if (!$policy = $modx->getObject('modAccessPolicy', $policyId)) {
        return $modx->log(modX::LOG_LEVEL_ERROR, $modx->lexicon('policy_err_nf'));
    }
} else {
    $policyId = $policy->id;
}

$policyData = array_merge($policy->get('data'), $accessPolicy);
$policy->set('data', $modx->toJSON($policyData));

if ($policy->save() == false) {
    return $modx->log(modX::LOG_LEVEL_ERROR, $modx->lexicon('policy_err_save'));
}


// Создаем роль
if ($role = $modx->getObject('modUserGroupRole', array('name' => $NAME))) {
    $roleId = $role->id;
} else {
    $response = $modx->runProcessor('security/role/create', array(
        'name' => $NAME,
        'authority' => $roleAuthority,

    ));

    if ($response->isError()) {
        return $modx->log(modX::LOG_LEVEL_ERROR, $response->getMessage());
    }
    $roleId = $response->getObject()['id'];
}

// Создаем группу пользователей
if ($group = $modx->getObject('modUserGroup', array('name' => $NAME))) {
    $groupId = $group->id;
} else {
    $response = $modx->runProcessor('security/group/create', array(
        'name' => $groupName,
        'parent' => 1,
        'aw_contexts' => 'web',

    ));

    if ($response->isError()) {
        return $modx->log(modX::LOG_LEVEL_ERROR, $response->getMessage());
    }
    $groupId = $response->getObject()['id'];
}

// Добавляем контекст - mgr в группу пользователей
$contextData = array(
    'target' => 'mgr',
    'authority' => $roleAuthority,
    'policy' => $policyId,
    'principal' => $groupId,

);

if ($context = $modx->getObject('modAccessContext', $contextData)) {
    $contextId = $context->id;
} else {
    $response = $modx->runProcessor('security/access/usergroup/context/create', $contextData);

    if ($response->isError()) {
        return $modx->log(modX::LOG_LEVEL_ERROR, $response->getMessage());
    }
    $contextId = $response->getObject()['id'];
}

// Редактируем контекст - web для группу пользователей
if ($contextWeb = $modx->getObject('modAccessContext', array('target' => 'web', 'principal' => $groupId))) {
    $response = $modx->runProcessor('security/access/usergroup/context/update', array(
        'id' => $contextWeb->id,
        'target' => 'web',
        'authority' => $roleAuthority,
        'policy' => 2, //Политика доступа - Administrator.
        'principal' => $groupId,
    ));

    if ($response->isError()) {
        return $modx->log(modX::LOG_LEVEL_ERROR, $response->getMessage());
    }
} else {
    $modx->log(modX::LOG_LEVEL_ERROR, 'Not find context Web');
}

// Создаем пользователей и добовляем в группу
$modx->setOption('password_min_length',6);

foreach ($users as $key => $user) {
    $isEmail = isset($user['email']) && !empty($user['email']);
    if ($u = $modx->getObject('modUser', array('username' => $user['username']))) {
        $userId = $u->id;
    } else {
        $response = $modx->runProcessor('security/user/create', array(
            'username' => $user['username'],
            'active' => 1,
            'class_key' => 'modUser',
            'newpassword' => false,
            'passwordnotifymethod' => $isEmail ? 'e' : 's',
            'passwordgenmethod' => 'spec',
            'specifiedpassword' => $user['password'],
            'confirmpassword' => $user['password'],
            'email' => $isEmail ? $user['email'] : $key . '@' . MODX_HTTP_HOST,
        ));

        if ($response->isError()) {
            $modx->log(modX::LOG_LEVEL_ERROR, $response->getMessage());
            continue;
        }
        $modx->error->reset();
        $userId = $response->getObject()['id'];

        $groupMemberData = array(
            'member' => $userId,
            'user_group' => $groupId,
            'role' => $roleId,
        );

        if (!$UserGroupMember = $modx->getObject('modUserGroupMember', $groupMemberData)) {
            $UserGroupMember = $modx->newObject('modUserGroupMember');
            $UserGroupMember->fromArray($groupMemberData);
            if (!$UserGroupMember->save()) {
                $modx->log(modX::LOG_LEVEL_ERROR, 'Error save user in group');
            }
        }
    }
}

if (!empty($mediaSourcePath)) {
    // Редактирование прав доступа для источника файлов Filesystem
    $mediaAccessSourceData = array(
        'target' => 1, // Filesystem ID
        'principal_class' => 'modUserGroup',
        'principal' => 1, // Группа пользователей - Administrator
        'authority' => 0, // Минимальная роль
        'policy' => 8,    // Политика - Media Source Admin
        'context_key' => '',
    );

    if (!$acl = $modx->getObject('sources.modAccessMediaSource', $mediaAccessSourceData)) {
        $acl = $modx->newObject('sources.modAccessMediaSource');
        $acl->fromArray($mediaAccessSourceData, '', true, true);
        if (!$acl->save()) {
            return $modx->log(modX::LOG_LEVEL_ERROR, 'Error update access source data Filesystem');
        }
    }

    // Создаем источник файлов
    if (!is_dir(MODX_BASE_PATH . $mediaSourcePath)) {
        if (!$modx->cacheManager->writeTree(MODX_BASE_PATH . $mediaSourcePath)) {
            $modx->log(modX::LOG_LEVEL_ERROR, 'Error create dir for media source ' . $mediaSourceName);
        }
    }

    $mediaSourceData = array(
        'name' => $mediaSourceName,
        'class_key' => 'sources.modFileMediaSource',
    );

    if (!$mediaSource = $modx->getObject('sources.modMediaSource', $mediaSourceData)) {
        $response = $modx->runProcessor('source/create', $mediaSourceData);
        if ($response->isError()) {
            return $modx->log(modX::LOG_LEVEL_ERROR, $response->getMessage());
        }
        $mediaSourceId = $response->getObject()['id'];
        $mediaSource = $modx->getObject('sources.modMediaSource', $mediaSourceId);
    }

    $mediaSourceProperties = $mediaSource->getProperties();
    $mediaSourceProperties['basePath']['value'] = '/' . $mediaSourcePath;
    $mediaSourceProperties['baseUrl']['value'] = $mediaSourcePath;
    $mediaSource->setProperties($mediaSourceProperties);

    if (!$mediaSource->save()) {
        return $modx->log(modX::LOG_LEVEL_ERROR, 'Error save media source for ' . $mediaSourceName);
    }

    $mediaAccessSourceData = array(
        'target' => $mediaSource->id,
        'principal_class' => 'modUserGroup',
        'principal' => $groupId,
        'authority' => $roleAuthority,
        'policy' => 8,    // Политика - Media Source Admin
        'context_key' => '',
    );

    if (!$acl = $modx->getObject('sources.modAccessMediaSource', $mediaAccessSourceData)) {
        $acl = $modx->newObject('sources.modAccessMediaSource');
        $acl->fromArray($mediaAccessSourceData, '', true, true);
        if (!$acl->save()) {
            return $modx->log(modX::LOG_LEVEL_ERROR, 'Error update access source data ' . $mediaSourceName);
        }
    }

    // Привязываем источник файлов ко всем tv
    if ($bindMediaSourceTv && $tvs = $modx->getCollection('modTemplateVar')) {
        foreach ($tvs as $tv) {
            $sourceElements = $modx->getCollection('sources.modMediaSourceElement', array(
                'object' => $tv->id,
                'object_class' => 'modTemplateVar',
                'context_key' => $contextKey,
            ));
            foreach ($sourceElements as $sourceElement) {
                $sourceElement->remove();
            }
            $sourceElement = $modx->newObject('sources.modMediaSourceElement');
            $sourceElement->fromArray(array(
                'object' => $tv->id,
                'object_class' => $tv->_class,
                'context_key' => $contextKey,
            ), '', true, true);
            $sourceElement->set('source', $mediaSource->id);
            $sourceElement->save();
        }
    }
}

// Перезагрузить все права доступа и очистить кэш.
$modx->runProcessor('security/access/flush', array());

$modx->setLogLevel(modX::LOG_LEVEL_INFO);
$modx->log(modX::LOG_LEVEL_INFO, 'success!!');