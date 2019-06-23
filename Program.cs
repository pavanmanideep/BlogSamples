using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Microsoft.Xrm.Sdk.Messages;
using Microsoft.Xrm.Sdk.Query;
using System.ServiceModel.Description;
using System.Net;
using Microsoft.Xrm.Sdk;
using Microsoft.Xrm.Sdk.Client;
using Microsoft.Crm.Sdk.Messages;

namespace MFA_Check
{
    class Program
    {
        static void Main(string[] args)
        {
            IOrganizationService service = ConnecttoCustomerEngagement();
            if (service != null)
            {
                Console.ReadLine();
                Console.WriteLine();
                //code your logic here
            }
        }

        public static IOrganizationService ConnecttoCustomerEngagement()
        {
            IOrganizationService organizationService = null;

            String username = "pavanmanideep@abecellors.onmicrosoft.com";//eg: abc@xyz.onmicrosoft.com
            String password = "nxlcndshjzfnjhxn";//eg: password@123

            // Get the URL from CRM, Navigate to Settings -> Customizations -> Developer Resources
            // Copy and Paste Organization Service Endpoint Address URL
            String url = "https://abecellors.api.crm8.dynamics.com/XRMServices/2011/Organization.svc"; //eg: https://<yourorganisationname>.api.crm8.dynamics.com/XRMServices/2011/Organization.svc
            try
            {
                ClientCredentials clientCredentials = new ClientCredentials();
                clientCredentials.UserName.UserName = username;
                clientCredentials.UserName.Password = password;

                // For Dynamics 365 Customer Engagement V9.X, set Security Protocol as TLS12
                ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12;

                organizationService = (IOrganizationService)new OrganizationServiceProxy(new Uri(url), null, clientCredentials, null);

                if (organizationService != null)
                {
                    Guid gOrgId = ((WhoAmIResponse)organizationService.Execute(new WhoAmIRequest())).OrganizationId;
                    if (gOrgId != Guid.Empty)
                    {
                        Console.WriteLine("Connection Established Successfully...");
                    }
                }
                else
                {
                    Console.WriteLine("Failed to Established Connection!!!");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("Exception occured - " + ex.Message);
            }
            return organizationService;

        }

    }
}
