module LibKvHelper
  # @returns Hash with Hiera configuraton for libkv local filesystem file store
  def libkv_file_hieradata
    {
      'libkv::options' => {
        'backend'  =>  'default',
        'backends' => {
          'default' => {
            'type' => 'file',
            'id'   => 'test'
          }
        }
      }
    }
  end
end
