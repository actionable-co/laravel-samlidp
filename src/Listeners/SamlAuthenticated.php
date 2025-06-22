<?php

namespace CodeGreenCreative\SamlIdp\Listeners;

use Illuminate\Auth\Events\Authenticated;
use CodeGreenCreative\SamlIdp\Jobs\SamlSso;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Str;

class SamlAuthenticated
{
    /**
     * Listen for the Authenticated event
     *
     * @param  Authenticated $event [description]
     * @return [type]               [description]
     */
    public function handle(Authenticated $event)
    {
        Log::info('RelayState debug', [
            'RelayState_raw' => request()->input('RelayState'),
            'query' => request()->query()
        ]);
        if (
            in_array($event->guard, config('samlidp.guards')) &&
            request()->filled('SAMLRequest') &&
            !request()->is('saml/logout') &&
            request()->isMethod('get')
        ) {
            abort(response(SamlSso::dispatchSync($event->guard), 302));
        }

        $relayState = request()->input('RelayState');

        if ($relayState && filter_var($relayState, FILTER_VALIDATE_URL)) {
            foreach (config('samlidp.allowed_relay_domains', []) as $domain) {
                if (Str::startsWith($relayState, $domain)) {
                    session(['saml_relay_state' => $relayState]);
                    break;
                }
            }
        }

        if (!request()->filled('SAMLRequest')) {
            Log::error('SAMLRequest parameter is missing in the request.', ['userId' => $event->user->id]);
            return;
        }

        SamlSso::dispatch($event->user);
    }
}
