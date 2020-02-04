<?php

namespace DivineOmega\LaravelPasswordSecurityAudit\Console\Commands;

use DivineOmega\CliProgressBar\ProgressBar;
use DivineOmega\LaravelPasswordSecurityAudit\Objects\CrackedUser;
use Illuminate\Console\Command;
use Illuminate\Database\Eloquent\Model;

class PasswordAudit extends Command
{
    /**
     * The name and signature of the console command.
     *
     * @var string
     */
    protected $signature = 'security:password-audit {user-model}';

    /**
     * The console command description.
     *
     * @var string
     */
    protected $description = 'Audits the security of your user\'s passwords';

    /**
     * Create a new command instance.
     *
     * @return void
     */
    public function __construct()
    {
        parent::__construct();
    }

    /**
     * Execute the console command.
     *
     * @return mixed
     */
    public function handle()
    {
        $passwords = file(__DIR__ . '/../../../resources/password-list.txt');

        $userModelClass = $this->argument('user-model');

        if (!class_exists($userModelClass)) {
            $this->error('Specified user model is not a valid class.');
            exit;
        }

        $userModel = new $userModelClass();

        if (!$userModel instanceof Model) {
            $this->error('Specified user model is not a Eloquent model.');
            exit;
        }

        $query = $userModel->query()
            ->select([$userModel->getKeyName(), 'password']);

        $numUsers = $query->count();

        if ($numUsers <= 0) {
            $this->error('No users found.');
            exit;
        }

        $crackedUsers = collect();

        $progressBar = new ProgressBar();
        $progressBar->setMaxProgress($numUsers * count($passwords));
        $progressBar->display();

        $query->chunk(1000, function ($users) use ($passwords, $crackedUsers, $progressBar) {

            /** @var Model $user */
            foreach ($users as  $user) {
                foreach($passwords as $i => $password) {
                    $hash = $user->password;
                    $passwordFound = password_verify($password, $hash);

                    if ($passwordFound) {
                        $crackedUsers->push(
                            new CrackedUser($user->getKey(), $password, $hash)
                        );
                    }

                    $progressBar->advance()->display();
                }

            }

        });

        $progressBar->complete();

        $crackedUsersCount = $crackedUsers->count();

        $this->line($crackedUsersCount.' user password(s) were found to be weak.');

        if ($crackedUsersCount > 0) {
            $this->table(['Key', 'Password', 'Hash'], $crackedUsers->toArray());
        }

    }
}