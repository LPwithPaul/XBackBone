<?php

namespace App\Controllers\Auth;

use App\Controllers\Controller;
use App\Database\Repositories\UserRepository;
use App\Web\ValidationHelper;
use League\OAuth2\Client\Provider\GenericProvider;
use Psr\Http\Message\ResponseInterface as Response;
use Psr\Http\Message\ServerRequestInterface as Request;

class OAuthController extends Controller
{
    protected function getProvider(): GenericProvider
    {
        $config = $this->config['oauth']; // Holt die Einstellungen aus config.php → 'oauth'-Block

        return new GenericProvider([
            'clientId'                => $config['clientId'],
            'clientSecret'            => $config['clientSecret'],
            'redirectUri'             => $config['redirectUri'],
            'urlAuthorize'            => $config['urlAuthorize'],
            'urlAccessToken'          => $config['urlAccessToken'],
            'urlResourceOwnerDetails' => $config['urlResourceOwnerDetails'],
            'scopes'                  => $config['scopes'] ?? [],
            'scopeSeparator'          => $config['scopeSeparator'] ?? ' ',
        ]);
    }

    /**
     * @param  Request  $request
     * @param  Response  $response
     *
     * @return Response
     * @throws \Exception
     *
     */
    public function redirect(Request $request, Response $response): Response
    {   
        if ($this->session->get('logged', false)) {
            return redirect($response, route('home'));
        }

        $provider = $this->getProvider();
        $authorizationUrl = $provider->getAuthorizationUrl();

        $this->session->set('oauth_state', $provider->getState());

        return redirect($response, $authorizationUrl);
    }

    /**
     * @param  Request  $request
     * @param  Response  $response
     *
     * @return Response
     * @throws \Exception
     *
     */
    public function callback(Request $request, Response $response): Response
    {   
        /** @var ValidationHelper $validator */
        $validator = make(ValidationHelper::class);
        $provider = $this->getProvider();
        //State verification
        if (empty($_GET['state']) || ($_GET['state'] !== $this->session->get('oauth_state', $_GET['state']))) {
            unset($_SESSION['oauth_state']);
            exit('Invalid state, make sure the URL has not been tampered with');
        }
        try {
            $accessToken = $provider->getAccessToken('authorization_code', [
                'code' => $_GET['code']
            ]);
            $resourceOwner = $provider->getResourceOwner($accessToken);
            $ownerData = $resourceOwner->toArray();

            $user = $this->database->query('SELECT `id`, `email`, `username`, `password`,`is_admin`, `active`, `current_disk_quota`, `max_disk_quota`, `ldap`, `copy_raw` FROM `users` WHERE `username` = ? OR `email` = ? LIMIT 1', [$ownerData['preferred_username'], $ownerData['email']])->fetch();
            if (!$user) {
                $activateToken = bin2hex(random_bytes(16));
                $password = bin2hex(random_bytes(16));

                make(UserRepository::class)->create(
                    $ownerData['email'],
                    $ownerData['preferred_username'],
                    $password,
                    (in_array($this->config['oauth']['groups']['admin'], $ownerData['groups']) === true) ? 1 : 0,
                    1,
                    (int) $this->getSetting('default_user_quota', -1),
                    $activateToken
                );
                echo "New registration: ". $ownerData['preferred_username'] ."<br>";
                return redirect($response, route('oauth.redirect'));
            } else {
                if ($user->email !== $ownerData['email']) {
                    $this->database->query('UPDATE `users` SET `email` = ? WHERE `id` = ?', [$ownerData['email'], $user->id]);
                }
                echo "is_admin: " . $user->is_admin . "<br>";
                echo "ownerData: " . in_array($this->config['oauth']['groups']['admin'], $ownerData['groups']) . "<br>";
                if ($user->is_admin !== in_array($this->config['oauth']['groups']['admin'], $ownerData['groups'])) {
                    $should_be_admin = in_array($this->config['oauth']['groups']['admin'], $ownerData['groups']) ? 1 : 0;
                    $this->database->query('UPDATE `users` SET `is_admin` = ? WHERE `id` = ?', [$should_be_admin, $user->id]);
                    $user->is_admin = $should_be_admin;
                }
                $validator
                    ->alertIf(!$user, 'bad_login')
                    ->alertIf(isset($this->config['maintenance']) && $this->config['maintenance'] && !($user->is_admin ?? true), 'maintenance_in_progress', 'info')
                    ->alertIf(!($user->active ?? false), 'account_disabled');

                if ($validator->fails()) {
                    if (!empty($request->getHeaderLine('X-Forwarded-For'))) {
                        $ip = $request->getHeaderLine('X-Forwarded-For');
                    } else {
                        $ip = $request->getServerParams()['REMOTE_ADDR'] ?? null;
                    }
                    $this->logger->info("Login failed with username='{$username}', ip={$ip}.");
                    return redirect($response, route('login'));
                }

                $this->session->set('logged', true)
                    ->set('user_id', $user->id)
                    ->set('username', $user->username)
                    ->set('admin', $user->is_admin)
                    ->set('copy_raw', $user->copy_raw);

                $this->setSessionQuotaInfo($user->current_disk_quota, $user->max_disk_quota);

                $this->session->alert(lang('welcome', [$user->username]), 'info');
                $this->logger->info("User $user->username logged in.");

                if ($this->session->has('redirectTo')) {
                    return redirect($response, $this->session->get('redirectTo'));
                }
                echo "why does this redirect not work?<br>";
                echo route('home')."<br>";
                //TODO return redirect($response, route('home')); does not work
                return redirect($response, route('home'));
            }
        } catch (\Exception $e) {
            exit('Failed to get access token: ' . $e->getMessage());
        }
    }
}