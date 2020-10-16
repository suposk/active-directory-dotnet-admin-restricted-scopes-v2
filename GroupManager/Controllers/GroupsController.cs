using GroupManager.Models;
using GroupManager.Utils;
//using Microsoft.Graph;
using Microsoft.Identity.Client;
using Newtonsoft.Json;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Threading.Tasks;
using System.Web.Mvc;

namespace GroupManager.Controllers
{
	public class GroupsController : Controller
	{
		// For simplicity, this sample uses an in-memory data store instead of a db.
		private ConcurrentDictionary<string, List<Models.Group>> groupList = new ConcurrentDictionary<string, List<Models.Group>>();

		[Authorize]
		// GET: Group
		public async Task<ActionResult> Index()
		{
			string tenantId = ClaimsPrincipal.Current.FindFirst(Globals.TenantIdClaimType).Value;

			try
			{
				ViewBag.TenantId = tenantId;
				return View();

				// Get a token for our admin-restricted set of scopes Microsoft Graph
				//string token = await GetGraphAccessToken(new string[] { "group.read.all" });
				//string token = await GetGraphAccessToken(new string[] { "user.read" });		
				string[] scopes = Globals.BasicSignInScopes.Split(new char[] { ' ' });			


				// Get a token for our admin-restricted set of scopes Microsoft Graph
				string token = await GetAccessToken(scopes);

				// Construct the groups query
				HttpClient client = new HttpClient();
				HttpRequestMessage request = new HttpRequestMessage(HttpMethod.Get, Globals.MicrosoftGraphGroupsApi);
				request.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", token);

				// Ensure a successful response
				HttpResponseMessage response = await client.SendAsync(request);
				response.EnsureSuccessStatusCode();

				// Populate the data store with the first page of groups
				string json = await response.Content.ReadAsStringAsync();
				GroupResponse result = JsonConvert.DeserializeObject<GroupResponse>(json);
				groupList[tenantId] = result.value;
			}
			catch (MsalUiRequiredException ex)
			{
				if (ex.ErrorCode == "user_null")
				{
					/*
					  If the tokens have expired or become invalid for any reason, ask the user to sign in again.
					  Another cause of this exception is when you restart the app using InMemory cache.
					  It will get wiped out while the user will be authenticated still because of their cookies, requiring the TokenCache to be initialized again
					  through the sign in flow.
					*/
					return new RedirectResult("/Account/SignIn/?redirectUrl=/Groups");
				}
				else if (ex.ErrorCode == "invalid_grant")
				{
					// If we got a token for the basic scopes, but not the admin-restricted scopes,
					// then we need to ask the admin to grant permissions by by connecting their tenant.
					return new RedirectResult("/Account/PermissionsRequired");
				}
				else
					return new RedirectResult("/Error?message=" + ex.Message);
			}
			// Handle unexpected errors.
			catch (Exception ex)
			{
				return new RedirectResult("/Error?message=" + ex.Message);
			}

			ViewBag.TenantId = tenantId;
			return View(groupList[tenantId]);
		}


		[Authorize]
		// GET: Group
		public async Task<ActionResult> Secure()
		{
			string tenantId = ClaimsPrincipal.Current.FindFirst(Globals.TenantIdClaimType).Value;

			try
			{
				//string[] scopes = Globals.BasicSignInScopes.Split(new char[] { ' ' });
				string[] scopes = new string[] { "https://graph.microsoft.com/.default" };

				// Get a token for our admin-restricted set of scopes Microsoft Graph
				string accessToken = await GetAccessToken(scopes);
				ViewBag.AccessToken = accessToken;

				var me = await this.GetMe(accessToken);
				var aleSecApi = await this.GetMe(accessToken, null);


				var score = await this.GetScore(accessToken);
				var alers = await this.GetAlerts(accessToken, "?$top=1");


				//var authenticationProvider = new Microsoft.Graph.DelegateAuthenticationProvider(
				//(requestMessage) =>
				//{
				//	requestMessage.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
				//	return Task.FromResult(0);
				//});


				//var graphClient = new Microsoft.Graph.GraphServiceClient(authenticationProvider);
				//try
				//{

				//	var alerts = await graphClient.Security.Alerts
				//		.Request()
				//		.GetAsync();

				//	var scores = await graphClient.Security.SecureScores
				//		.Request()
				//		.Top(1)
				//		.GetAsync();
				//}
				//catch (Exception ex)
				//{
				//	Debug.WriteLine($"Error: {ex.Message} {ex?.InnerException}");
				//}


				//// Construct the groups query
				//HttpClient client = new HttpClient();
				//HttpRequestMessage request = new HttpRequestMessage(HttpMethod.Get, Globals.MicrosoftGraphGroupsApi);
				//request.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", accessToken);

				//// Ensure a successful response
				//HttpResponseMessage response = await client.SendAsync(request);
				//response.EnsureSuccessStatusCode();

				//// Populate the data store with the first page of groups
				//string json = await response.Content.ReadAsStringAsync();
				//GroupResponse result = JsonConvert.DeserializeObject<GroupResponse>(json);
				//groupList[tenantId] = result.value;
			}
			catch (MsalUiRequiredException ex)
			{
				if (ex.ErrorCode == "user_null")
				{
					/*
					  If the tokens have expired or become invalid for any reason, ask the user to sign in again.
					  Another cause of this exception is when you restart the app using InMemory cache.
					  It will get wiped out while the user will be authenticated still because of their cookies, requiring the TokenCache to be initialized again
					  through the sign in flow.
					*/
					return new RedirectResult("/Account/SignIn/?redirectUrl=/Groups");
				}
				else if (ex.ErrorCode == "invalid_grant")
				{
					// If we got a token for the basic scopes, but not the admin-restricted scopes,
					// then we need to ask the admin to grant permissions by by connecting their tenant.
					return new RedirectResult("/Account/PermissionsRequired");
				}
				else
					return new RedirectResult("/Error?message=" + ex.Message);
			}
			// Handle unexpected errors.
			catch (Exception ex)
			{
				return new RedirectResult("/Error?message=" + ex.Message);
			}

			ViewBag.TenantId = tenantId;
			return View();
		}

		[Authorize]
		public async Task<ActionResult> ServiceManagement()
		{
			string tenantId = ClaimsPrincipal.Current.FindFirst(Globals.TenantIdClaimType).Value;
			var model = new ServiceManagementModel();
			try
			{

				string[] scopes = new string[] { "https://management.azure.com/.default" };
				string accessToken = await GetAccessToken(scopes);
				ViewBag.AccessToken = accessToken;
				var secCenter2 = await this.GetRes(accessToken, "https://management.azure.com/subscriptions/8d044d64-3e1a-4c50-8125-7e8762a074ab/providers/Microsoft.Security/secureScores?api-version=2020-01-01-preview");

				model.AccessToken = accessToken;
				model.Score = secCenter2;
			}
			catch (MsalUiRequiredException ex)
			{
				if (ex.ErrorCode == "user_null")
				{
					/*
					  If the tokens have expired or become invalid for any reason, ask the user to sign in again.
					  Another cause of this exception is when you restart the app using InMemory cache.
					  It will get wiped out while the user will be authenticated still because of their cookies, requiring the TokenCache to be initialized again
					  through the sign in flow.
					*/
					return new RedirectResult("/Account/SignIn/?redirectUrl=/Groups");
				}
				else if (ex.ErrorCode == "invalid_grant")
				{
					// If we got a token for the basic scopes, but not the admin-restricted scopes,
					// then we need to ask the admin to grant permissions by by connecting their tenant.
					return new RedirectResult("/Account/PermissionsRequired");
				}
				else
					return new RedirectResult("/Error?message=" + ex.Message);
			}
			// Handle unexpected errors.
			catch (Exception ex)
			{
				return new RedirectResult("/Error?message=" + ex.Message);
			}

			ViewBag.TenantId = tenantId;
			return View(model);
		}

		/// <summary>
		/// We obtain access token for Microsoft Graph with the scope "group.read.all". Since this access token was not obtained during the initial sign in process 
		/// (OnAuthorizationCodeReceived), the user will be prompted to consent again.
		/// </summary>
		/// <returns></returns>
		private async Task<string> GetAccessToken(string[] scopes)
		{

			try
			{
				IConfidentialClientApplication cc = MsalAppBuilder.BuildConfidentialClientApplication();
				IAccount userAccount = await cc.GetAccountAsync(ClaimsPrincipal.Current.GetMsalAccountId());

				AuthenticationResult result = await cc.AcquireTokenSilent(scopes, userAccount).ExecuteAsync();
				return result.AccessToken;
			}
			catch (Exception ex)
            {
				throw;
				//return null;
            }
		}

		public async Task<List<string>> GetAlerts(string accessToken, string queryParameter)
		{
			try
			{
				string endpoint = "https://graph.microsoft.com/v1.0/security/alerts"; queryParameter = string.Empty;

				using (var client = new HttpClient())
				{
					using (var request = new HttpRequestMessage(HttpMethod.Get, endpoint + queryParameter))
					{
						request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
						request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);

						using (var response = await client.SendAsync(request))
						{
							if (response.IsSuccessStatusCode)
							{
								string result = await response.Content.ReadAsStringAsync();
								//SecureScoreResult secureScoreResult = JsonConvert.DeserializeObject<SecureScoreResult>(result);
								//return secureScoreResult.Value;
								return new List<string> { result };
							}
							else
							{
								Debug.WriteLine($"Error: {response}");
								return null;
							}
						}
					}
				}
			}
			catch
			{
				return null;
			}
		}

		public async Task<string> GetRes(string accessToken, string endpoint = null)
		{
			try
			{
				string url = endpoint ?? "https://graph.microsoft.com/v1.0/me/";

				using (var client = new HttpClient())
				{
					using (var request = new HttpRequestMessage(HttpMethod.Get, url))
					{
						request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
						request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);

						using (var response = await client.SendAsync(request))
						{
							if (response.IsSuccessStatusCode)
							{
								string result = await response.Content.ReadAsStringAsync();
								return result;
							}
							else
							{
								Debug.WriteLine($"Error: {response}");
								return null;
							}
						}
					}
				}
			}
			catch
			{
				return null;
			}
		}

		public async Task<string> GetMe(string accessToken, string endpoint = null)
		{
			try
			{
				string url = endpoint ?? "https://graph.microsoft.com/v1.0/me/";

				using (var client = new HttpClient())
				{
					using (var request = new HttpRequestMessage(HttpMethod.Get, url))
					{
						request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
						request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);

						using (var response = await client.SendAsync(request))
						{
							if (response.IsSuccessStatusCode)
							{
								string result = await response.Content.ReadAsStringAsync();
								return result;
							}
							else
							{
								Debug.WriteLine($"Error: {response}");
								return null;
							}
						}
					}
				}
			}
			catch
			{
				return null;
			}
		}

		public async Task<List<object>> GetScore(string accessToken, string endpoint = null)
		{
			try
			{
				string url = endpoint ?? "https://graph.microsoft.com/beta/security/secureScores?$top=5";

				using (var client = new HttpClient())
				{
					using (var request = new HttpRequestMessage(HttpMethod.Get, url))
					{
						request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
						request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);

						using (var response = await client.SendAsync(request))
						{
							if (response.IsSuccessStatusCode)
							{
								string result = await response.Content.ReadAsStringAsync();
								//SecureScoreResult secureScoreResult = JsonConvert.DeserializeObject<SecureScoreResult>(result);
								//return secureScoreResult.Value;
								//return null;
								return new List<object> { result };
							}
							else
							{
								Debug.WriteLine($"Error: {response}");
								return null;
							}
						}
					}
				}
			}
			catch
			{
				return null;
			}
		}
	}
}