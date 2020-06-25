using System;
using System.Globalization;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Net.Http;
using System.Text;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using Newtonsoft.Json;

namespace SampleMvcApp.Controllers
{
    public class HomeController : Controller
    {

        public async Task<IActionResult> Index()
        {
            var mySecret = "asdv234234^&%&^%&^hjsdfb2%%%";
            var mySecurityKey = new SymmetricSecurityKey(Encoding.ASCII.GetBytes(mySecret));

            SecurityToken tokenS = null;
            // If the user is authenticated, then this is how you can get the access_token and id_token
            if (User.Identity.IsAuthenticated)
            {
                string accessToken = await HttpContext.GetTokenAsync("access_token");

                // if you need to check the access token expiration time, use this value
                // provided on the authorization response and stored.
                // do not attempt to inspect/decode the access token
                DateTime accessTokenExpiresAt = DateTime.Parse(
                    await HttpContext.GetTokenAsync("expires_at"),
                    CultureInfo.InvariantCulture,
                    DateTimeStyles.RoundtripKind);

                string idToken = await HttpContext.GetTokenAsync("id_token");

                // Now you can use them. For more info on when and how to use the
                // access_token and id_token, see https://auth0.com/docs/tokens
                var handler = new JwtSecurityTokenHandler();
                tokenS = handler.ReadToken(idToken) as SecurityToken;
                try
                {
                    HttpClient client = new HttpClient();
                    HttpResponseMessage response = await client.GetAsync("https://dev-5c-o51v2.au.auth0.com/.well-known/jwks.json");
                    string jwksJson = await response.Content.ReadAsStringAsync();
                    

                    var jwks = new JsonWebKeySet(jwksJson);
                    JsonWebKey jwk = jwks.Keys.First();

                    handler.ValidateToken(idToken, new TokenValidationParameters
                    {
                        IssuerSigningKey = jwk,
                        ValidAudience = "mhoZ0NPzDPbcE0uWTAWxzflpfAM71tYH",
                        ValidIssuer = "https://dev-5c-o51v2.au.auth0.com/"
                    }, out SecurityToken validatedToken);

                    tokenS = validatedToken;
                }
                catch(Exception ex)
                {
                    return View();
                }
            }

            var j = Json(tokenS).Value;
            
            if (tokenS == null)
                return View();

            return View(Json(tokenS).Value);
        }

        public IActionResult Error()
        {
            return View();
        }
    }
}
