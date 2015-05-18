<?php

function checkUser($login, $password)
{
    $baseDN = "ou=OrganizationalUnitExample,dc=domainExample,dc=domaineExtension(fr, net, com, org etc.)";
    $ldapServer = "ldap://ldap.example.com:389";
    $ldap_dn = 'cn=CommonNameExample,ou=OrganizationalUnitExample,dc=domainExample,dc=domaineExtension(fr, net, com, org etc.)'; // user par défaut
    $ldap_pwd = 'xxxxxx'; // password par défaut
    $result = array('finalResult' => false);

    if (empty($login) || empty($password)) {

        if (empty($login)) {
            $result['step'][] = array(
                'step' => 'Vérification présence login',
                'errorMessage' => 'login manquant',
                'status' => false
            );
        } else {
            $result['step'][] = array(
                'step' => 'Vérification présence login',
                'errorMessage' => '',
                'status' => true
            );
        }

        if (empty($password)) {
            $result['step'][] = array(
                'step' => 'Vérification présence password',
                'errorMessage' => 'password manquant',
                'status' => false
            );
        } else {
            $result['step'][] = array(
                'step' => 'Vérification présence password',
                'errorMessage' => '',
                'status' => true
            );
        }

        return $result;
    } // end if (empty($login) || empty($password))

    /********************************************************************************************************************/


    /* Connexion serveur */
    if (function_exists('ldap_connect')) {
        $conn = ldap_connect($ldapServer);
    } else {
        $result['step'][] = array(
            'step' => 'ldap_connect',
            'errorMessage' => "impossible d'exécuter ldap_connect (librairie non installée)",
            'status' => 501
        );
        return $result;
    }


    if ($conn) {
        $result['step'][] = array(
            'step' => 'Connexion au serveur',
            'errorMessage' => '',
            'status' => true
        );

        // On dit qu'on utilise LDAP V3, sinon la V2 par défaut est utilisé
        // et le bind ne passe pas.
        if (function_exists('ldap_set_option')) {
            if (ldap_set_option($conn, LDAP_OPT_PROTOCOL_VERSION, 3)) {
                $result['step'][] = array(
                    'step' => 'LDAPv3',
                    'errorMessage' => '',
                    'status' => true
                );

                ldap_set_option($conn, LDAP_OPT_REFERRALS, 0); // Pour liaison avec l'AD

                if ('Success' === ldap_error($conn)) {
                    $result['step'][] = array(
                        'step' => 'Liaison au serveur',
                        'errorMessage' => '',
                        'status' => true
                    );


                    if (function_exists('ldap_bind')) {
                        if ($res = @ldap_bind($conn, $ldap_dn, $ldap_pwd)) { // connexion avec l'utilisateur par défaut
                            $result['step'][] = array(
                                'step' => 'Bind au ldap avec le user par défaut',
                                'errorMessage' => '',
                                'status' => true
                            );

                            $attributes = array("dn", "cn");
                            $filter = "(&(objectClass=person)(objectClass=user)(|(cn=$login*)(mail=$login*)(uid=$login*)))";
                            $sr = ldap_search($conn, $baseDN, $filter, $attributes);

                            $nb_result = ldap_count_entries($conn, $sr);

                            if ($nb_result == 1) {
                                $result['step'][] = array(
                                    'step' => 'Recherche login',
                                    'errorMessage' => '',
                                    'status' => true
                                );

                                $info = ldap_get_entries($conn, $sr);

                                $dn_user = $info[0]["dn"];

                                $r = @ldap_bind($conn, $dn_user, $password);

                                if ($r === TRUE) {
                                    $result['step'][] = array(
                                        'step' => 'couple login/password vérifié',
                                        'errorMessage' => '',
                                        'status' => true
                                    );
                                    $result['finalResult'] = true;

                                    ldap_unbind($conn);
                                    @ldap_close($conn);

                                    return $result;
                                } elseif ($r === FALSE || ldap_errno($conn) == 16) {
                                    $result['step'][] = array(
                                        'step' => 'couple login/password vérifié',
                                        'errorMessage' => 'password incorrect',
                                        'status' => false
                                    );

                                    return $result;

                                } elseif ($r === -1) {
                                    $result['step'][] = array(
                                        'step' => 'couple login/password vérifié',
                                        'errorMessage' => 'erreur LDAP ' . ldap_error($conn),
                                        'status' => false
                                    );

                                    return $result;
                                }
                            } else { // end if ($nb_result == 1)
                                $result['step'][] = array(
                                    'step' => 'Recherche login',
                                    'errorMessage' => 'login non trouvé',
                                    'status' => false
                                );

                                return $result;
                            }
                        } else { // end if (!($res = ldap_bind($conn, $ldap_dn, $ldap_pwd)))
                            $result['step'][] = array(
                                'step' => 'Bind au ldap avec le user par défaut',
                                'errorMessage' => 'bind impossible au ldap',
                                'status' => false
                            );

                            return $result;
                        }
                    } else { // end if (function_exists('ldap_bind'))
                        $result['step'][] = array(
                            'step' => 'ldap_bind',
                            'errorMessage' => "impossible d'exécuter ldap_bind (librairie non installée)",
                            'status' => 501
                        );
                        
                        return $result;
                    }
                } else { // end if ('Success' === ldap_error($conn))
                    $result['step'][] = array(
                        'step' => 'Liaison au serveur',
                        'errorMessage' => 'échec de liaison au serveur',
                        'status' => false
                    );

                    return $result;
                }
            } else { // end if (ldap_set_option($conn, LDAP_OPT_PROTOCOL_VERSION, 3))
                $result['step'][] = array(
                    'step' => 'LDAPv3',
                    'errorMessage' => "Impossible d'utiliser LDAP V3",
                    'status' => false
                );

                return $result;
            }
        } else { // end if (function_exists('ldap_set_option'))
            $result['step'][] = array(
                'step' => 'ldap_set_option',
                'errorMessage' => "impossible d'exécuter ldap_set_option (librairie non installée)",
                'status' => 501
            );
            
            return $result;
        }
    } else { // end if($conn)
        $result['step'][] = array(
            'step' => 'Connexion au serveur',
            'errorMessage' => 'connexion impossible au serveur LDAP',
            'status' => false
        );

        return $result;
    }
}